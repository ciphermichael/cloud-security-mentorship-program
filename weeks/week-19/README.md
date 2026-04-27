# Week 19 — Threat Intelligence & CTI Integration

**Phase 5: Advanced Topics | CTI Enrichment Pipeline**

---

## Learning Objectives

By the end of this week you will be able to:

- Explain CTI frameworks: MITRE ATT&CK, Diamond Model, Cyber Kill Chain
- Ingest threat intelligence feeds from AlienVault OTX, Abuse.ch, and AbuseIPDB (all free)
- Build a CTI enrichment pipeline that adds threat actor context to GuardDuty findings
- Create an IOC lookup service for IPs, domains, file hashes, and URLs
- Write CTI-enriched alert notifications with threat actor TTPs
- Understand how to evaluate IOC quality and freshness

---

## Daily Breakdown

| Day | Focus | Time |
|-----|-------|------|
| Mon | CTI fundamentals — Diamond Model, Kill Chain, ATT&CK, IOC types, TLP markings | 2 hrs |
| Tue | AlienVault OTX and AbuseIPDB API integration — rate limits, pagination, caching | 2 hrs |
| Wed | Build IOC enrichment pipeline — IP lookup, domain lookup, hash lookup | 2 hrs |
| Thu | Connect to GuardDuty — enrich every finding with CTI context | 2 hrs |
| Fri | Enriched Slack/SNS notifications with threat actor context | 2 hrs |
| Sat | IOC dashboard, documentation, push to GitHub | 3 hrs |
| Sun | Mentor review — CTI interview prep | 1 hr |

---

## Topics Covered

### CTI Frameworks

**MITRE ATT&CK** — a knowledge base of adversary tactics, techniques, and procedures organized by attack phase. Used for detection coverage mapping and threat actor profiling. `https://attack.mitre.org`

**Cyber Kill Chain (Lockheed Martin)** — 7 stages of an attack: Reconnaissance → Weaponization → Delivery → Exploitation → Installation → Command & Control → Actions on Objectives. Useful for thinking about where to detect and disrupt.

**Diamond Model** — analyzes intrusions using 4 core features: Adversary, Infrastructure, Capability, Victim. Connects threat actors to their tools and infrastructure.

### IOC Types and Quality

| IOC Type | Example | Freshness Window | Reliability |
|----------|---------|-----------------|-------------|
| IP Address | 198.51.100.42 | Hours to days | Low — IPs rotate |
| Domain | evil-c2.example.com | Days to weeks | Medium |
| File hash (SHA-256) | d41d8cd9... | Months to years | High — doesn't change |
| URL | http://evil/payload.exe | Hours to days | Low |
| Email | attacker@evil.com | Days to weeks | Medium |
| YARA rule | Matches on file content patterns | Long-lived | Very high |

**TLP (Traffic Light Protocol) marking:**
- TLP:RED — not for disclosure, recipients only
- TLP:AMBER — limited disclosure, need-to-know
- TLP:GREEN — community sharing, no public disclosure
- TLP:WHITE (CLEAR) — unlimited disclosure

### Free CTI Feeds

| Feed | URL | What It Has |
|------|-----|-------------|
| AlienVault OTX | `https://otx.alienvault.com/api/v1/` | IPs, domains, hashes, malware families |
| AbuseIPDB | `https://api.abuseipdb.com/api/v2/` | IP abuse reports with categories |
| Abuse.ch URLhaus | `https://urlhaus-api.abuse.ch/v1/` | Malicious URLs |
| Abuse.ch MalwareBazaar | `https://mb-api.abuse.ch/api/v1/` | Malware hashes |
| Shodan (free tier) | `https://api.shodan.io/` | Internet-exposed service info |
| Feodo Tracker | `https://feodotracker.abuse.ch/` | C2 IPs |

---

## Instructor Mentoring Guidance

**Week 19 ties the program together with intelligence context.** Raw detection alerts become actionable intelligence when enriched with "who is doing this and why."

**Key coaching points:**
- IOC enrichment is only as good as the feed quality. Discuss false positive risk — a shared IP (VPN exit node, Tor exit) might be flagged as malicious for every user.
- Always check the confidence score and last seen date before acting on an IOC match.
- Building a local IOC cache is critical — don't call external APIs on every alert, API rate limits will bite you.

**Mentoring session agenda (60 min):**
1. (10 min) Show a real GuardDuty finding enriched with OTX context — how much more useful is it?
2. (20 min) Code review of the enrichment pipeline — error handling, caching, rate limiting
3. (20 min) Mock interview: "Our GuardDuty alert shows an IP we don't recognize. How do you investigate it?"
4. (10 min) Preview Weeks 20-24 — career prep and capstone

---

## Hands-on Lab

### Lab 1: AlienVault OTX API Integration

```bash
# Sign up for a free OTX account
# https://otx.alienvault.com/api
# Get your API key from Settings → API Integration

# Test the API
export OTX_API_KEY="your-key-here"
curl -H "X-OTX-API-KEY: $OTX_API_KEY" \
  "https://otx.alienvault.com/api/v1/indicators/IPv4/198.51.100.42/general"
```

```python
# src/cti_enricher.py
import os
import json
import hashlib
import requests
import time
from datetime import datetime, timezone, timedelta
from pathlib import Path
from dataclasses import dataclass, asdict
from functools import lru_cache

OTX_BASE = 'https://otx.alienvault.com/api/v1'
ABUSEIPDB_BASE = 'https://api.abuseipdb.com/api/v2'
CACHE_TTL_HOURS = 24
CACHE_DIR = Path('.cti-cache')


@dataclass
class IOCResult:
    ioc_type: str        # ip, domain, hash, url
    ioc_value: str
    is_malicious: bool
    confidence: int      # 0-100
    threat_names: list
    threat_actor: str
    ttps: list[str]      # MITRE technique IDs
    last_seen: str
    references: list[str]
    sources: list[str]
    raw: dict


class CTIEnricher:

    def __init__(self):
        self.otx_key = os.environ.get('OTX_API_KEY', '')
        self.abuseipdb_key = os.environ.get('ABUSEIPDB_KEY', '')
        CACHE_DIR.mkdir(exist_ok=True)

    def _cache_key(self, ioc_type: str, value: str) -> Path:
        h = hashlib.md5(f'{ioc_type}:{value}'.encode()).hexdigest()
        return CACHE_DIR / f'{h}.json'

    def _cache_get(self, ioc_type: str, value: str) -> dict | None:
        path = self._cache_key(ioc_type, value)
        if not path.exists():
            return None
        data = json.loads(path.read_text())
        cached_at = datetime.fromisoformat(data.get('_cached_at', '2000-01-01'))
        if datetime.now(timezone.utc) - cached_at > timedelta(hours=CACHE_TTL_HOURS):
            path.unlink()
            return None
        return data

    def _cache_set(self, ioc_type: str, value: str, data: dict):
        path = self._cache_key(ioc_type, value)
        data['_cached_at'] = datetime.now(timezone.utc).isoformat()
        path.write_text(json.dumps(data))

    def _otx_request(self, endpoint: str) -> dict:
        """Make an OTX API request with caching and error handling."""
        cached = self._cache_get('otx', endpoint)
        if cached:
            return cached

        headers = {'X-OTX-API-KEY': self.otx_key}
        try:
            resp = requests.get(f'{OTX_BASE}{endpoint}', headers=headers, timeout=10)
            resp.raise_for_status()
            data = resp.json()
            self._cache_set('otx', endpoint, data)
            time.sleep(0.5)  # Respect rate limits
            return data
        except requests.RequestException as e:
            print(f'  [WARN] OTX API error: {e}')
            return {}

    def _abuseipdb_request(self, ip: str) -> dict:
        """Check an IP against AbuseIPDB."""
        cached = self._cache_get('abuseipdb', ip)
        if cached:
            return cached

        headers = {'Key': self.abuseipdb_key, 'Accept': 'application/json'}
        params = {'ipAddress': ip, 'maxAgeInDays': 90, 'verbose': True}
        try:
            resp = requests.get(f'{ABUSEIPDB_BASE}/check',
                               headers=headers, params=params, timeout=10)
            resp.raise_for_status()
            data = resp.json()
            self._cache_set('abuseipdb', ip, data)
            time.sleep(0.5)
            return data
        except requests.RequestException as e:
            print(f'  [WARN] AbuseIPDB error: {e}')
            return {}

    def lookup_ip(self, ip: str) -> IOCResult:
        """Enrich an IP address with CTI context."""
        # OTX lookup
        otx = self._otx_request(f'/indicators/IPv4/{ip}/general')
        otx_pulses = self._otx_request(f'/indicators/IPv4/{ip}/malware')
        # AbuseIPDB lookup
        abuse = self._abuseipdb_request(ip)

        # Parse OTX
        pulse_names = [p.get('name', '') for p in otx.get('pulse_info', {}).get('pulses', [])]
        otx_malicious = otx.get('pulse_info', {}).get('count', 0) > 0
        ttps = []
        for pulse in otx.get('pulse_info', {}).get('pulses', []):
            for tag in pulse.get('tags', []):
                if tag.startswith('T'):
                    ttps.append(tag)

        # Parse AbuseIPDB
        abuse_data = abuse.get('data', {})
        abuse_score = abuse_data.get('abuseConfidenceScore', 0)
        abuse_malicious = abuse_score > 25
        abuse_categories = abuse_data.get('usageType', '')

        is_malicious = otx_malicious or abuse_malicious
        confidence = max(
            min(otx.get('pulse_info', {}).get('count', 0) * 10, 100),
            abuse_score
        )

        return IOCResult(
            ioc_type='ip',
            ioc_value=ip,
            is_malicious=is_malicious,
            confidence=confidence,
            threat_names=pulse_names[:5],
            threat_actor='',  # OTX free tier doesn't always return this
            ttps=list(set(ttps))[:10],
            last_seen=abuse_data.get('lastReportedAt', ''),
            references=[f'https://otx.alienvault.com/indicator/ip/{ip}',
                        f'https://www.abuseipdb.com/check/{ip}'],
            sources=['AlienVault OTX', 'AbuseIPDB'] if self.abuseipdb_key else ['AlienVault OTX'],
            raw={'otx': otx, 'abuseipdb': abuse_data}
        )

    def lookup_hash(self, sha256: str) -> IOCResult:
        """Check a file hash against CTI feeds."""
        otx = self._otx_request(f'/indicators/file/{sha256}/general')
        pulse_count = otx.get('pulse_info', {}).get('count', 0)
        pulse_names = [p.get('name', '') for p in otx.get('pulse_info', {}).get('pulses', [])]

        return IOCResult(
            ioc_type='hash',
            ioc_value=sha256,
            is_malicious=pulse_count > 0,
            confidence=min(pulse_count * 20, 100),
            threat_names=pulse_names[:5],
            threat_actor='',
            ttps=[],
            last_seen='',
            references=[f'https://otx.alienvault.com/indicator/file/{sha256}'],
            sources=['AlienVault OTX'],
            raw={'otx': otx}
        )

    def enrich_guardduty_finding(self, finding: dict) -> dict:
        """Add CTI context to a GuardDuty finding."""
        finding_type = finding.get('type', '')
        service = finding.get('service', {})
        remote_ip = (service.get('action', {})
                     .get('networkConnectionAction', {})
                     .get('remoteIpDetails', {})
                     .get('ipAddressV4', ''))

        enrichment = {
            'ioc_results': [],
            'is_known_threat': False,
            'threat_context': [],
            'recommended_action': 'Investigate'
        }

        if remote_ip:
            print(f'    Enriching IP: {remote_ip}')
            ioc = self.lookup_ip(remote_ip)
            enrichment['ioc_results'].append(asdict(ioc))
            if ioc.is_malicious:
                enrichment['is_known_threat'] = True
                enrichment['threat_context'] = ioc.threat_names
                enrichment['recommended_action'] = 'AUTO-BLOCK: Known malicious IP'

        finding['cti_enrichment'] = enrichment
        return finding


def enrich_guardduty_findings(region: str = 'us-east-1') -> list[dict]:
    """Pull and enrich all active GuardDuty findings."""
    import boto3
    gd = boto3.client('guardduty', region_name=region)
    enricher = CTIEnricher()

    # Get detector ID
    detectors = gd.list_detectors()['DetectorIds']
    if not detectors:
        print('[WARN] No GuardDuty detectors found')
        return []

    detector_id = detectors[0]
    finding_ids = gd.list_findings(
        DetectorId=detector_id,
        FindingCriteria={
            'Criterion': {
                'service.archived': {'Eq': ['false']},
                'severity': {'Gte': 4}  # Medium and above
            }
        }
    )['FindingIds']

    if not finding_ids:
        print('[*] No active findings')
        return []

    findings = gd.get_findings(
        DetectorId=detector_id,
        FindingIds=finding_ids[:20]  # Max 20 at a time
    )['Findings']

    enriched = []
    for finding in findings:
        print(f'[*] Enriching finding: {finding.get("Type", "")}')
        enriched.append(enricher.enrich_guardduty_finding(finding))

    return enriched
```

### Lab 2: IOC Watchlist from Abuse.ch

```python
# scripts/fetch_c2_watchlist.py
"""Download Feodo Tracker C2 IP blocklist and store as JSON."""
import requests
import json
from pathlib import Path
from datetime import datetime, timezone

FEODO_URL = 'https://feodotracker.abuse.ch/downloads/ipblocklist.json'
URLHAUS_URL = 'https://urlhaus-api.abuse.ch/v1/urls/recent/'


def fetch_feodo_blocklist() -> list[dict]:
    resp = requests.get(FEODO_URL, timeout=30)
    resp.raise_for_status()
    return resp.json()


def fetch_urlhaus_recent() -> list[dict]:
    resp = requests.post(URLHAUS_URL, data={'limit': 100}, timeout=30)
    resp.raise_for_status()
    return resp.json().get('urls', [])


if __name__ == '__main__':
    out = Path('threat-intel')
    out.mkdir(exist_ok=True)

    print('[*] Fetching Feodo Tracker C2 IPs...')
    c2_ips = fetch_feodo_blocklist()
    (out / 'c2-ips.json').write_text(json.dumps({
        'updated': datetime.now(timezone.utc).isoformat(),
        'source': 'Feodo Tracker / Abuse.ch',
        'count': len(c2_ips),
        'ips': c2_ips
    }, indent=2))
    print(f'    {len(c2_ips)} C2 IPs saved')

    print('[*] Fetching URLhaus malicious URLs...')
    urls = fetch_urlhaus_recent()
    (out / 'malicious-urls.json').write_text(json.dumps({
        'updated': datetime.now(timezone.utc).isoformat(),
        'source': 'URLhaus / Abuse.ch',
        'count': len(urls),
        'urls': urls
    }, indent=2))
    print(f'    {len(urls)} malicious URLs saved')
```

---

## Interview Skills Gained

**Q: What is threat intelligence and how is it different from a security alert?**
> A security alert tells you something suspicious happened (GuardDuty: connection to known-bad IP). Threat intelligence provides context: who is the adversary, what are their motivations, what TTPs do they use, what infrastructure have they been seen using? Enriched with CTI, that alert becomes: "Connection to IP used by APT29 (Cozy Bear), associated with credential harvesting campaigns, last reported 2 days ago."

**Q: What are IOCs and how do you use them in cloud security?**
> Indicators of Compromise are artifacts that indicate a system may have been breached — IPs, domains, file hashes, URLs. In cloud security: (1) check GuardDuty alert source IPs against threat feeds to determine if they're known malicious infrastructure, (2) check process hashes in EC2 instances against malware databases, (3) build blocklists for WAF/Security Groups from C2 IP feeds. Always consider IOC age and confidence before acting.

**Q: What is TLP and why does it matter for threat sharing?**
> Traffic Light Protocol is a framework for controlling how threat intelligence is shared. TLP:RED means only the recipient can see it. TLP:AMBER means limited sharing within the recipient's organization. TLP:GREEN means sharing within the security community. TLP:WHITE/CLEAR means unrestricted sharing. Using TLP incorrectly — sharing RED intelligence publicly — violates information sharing agreements and can burn human sources or alert adversaries that they've been detected.

---

## Submission Checklist

- [ ] CTI enricher working with AlienVault OTX (at minimum — AbuseIPDB optional)
- [ ] Local cache preventing redundant API calls
- [ ] GuardDuty finding enrichment working (real or mock findings)
- [ ] Feodo/URLhaus IOC watchlist fetcher working
- [ ] Enriched Slack/SNS notification with threat context (screenshot)
- [ ] IOC dashboard or table showing enriched findings
- [ ] README explains the threat feeds used, their limitations, and how to interpret results

---

## Links

→ Next: [Week 20 — Career Prep & Portfolio Polish](../week-20/README.md)
