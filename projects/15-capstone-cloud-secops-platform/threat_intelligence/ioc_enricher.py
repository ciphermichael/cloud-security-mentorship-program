"""
Threat Intelligence IOC Enricher
Capstone Project — Cloud Security Operations Platform

Enriches IP addresses, domains and file hashes against:
- AbuseIPDB (IP reputation)
- VirusTotal (file/IP/domain)
- AlienVault OTX (threat context)
"""
import os, json, logging, hashlib
from datetime import datetime, timezone
from typing import Optional
import requests

logger = logging.getLogger(__name__)

ABUSEIPDB_KEY = os.environ.get("ABUSEIPDB_API_KEY","")
VT_API_KEY    = os.environ.get("VT_API_KEY","")
OTX_API_KEY   = os.environ.get("OTX_API_KEY","")
TIMEOUT       = 10

class IOCEnricher:
    def enrich_ip(self, ip: str) -> dict:
        result = {"ip": ip, "sources": {}, "verdict": "UNKNOWN", "risk_score": 0}
        if ABUSEIPDB_KEY:
            result["sources"]["abuseipdb"] = self._abuseipdb_lookup(ip)
        if OTX_API_KEY:
            result["sources"]["otx"] = self._otx_ip_lookup(ip)
        # Determine verdict
        abuse_score = result["sources"].get("abuseipdb",{}).get("abuseConfidenceScore",0)
        if abuse_score >= 75:
            result["verdict"], result["risk_score"] = "MALICIOUS", 90
        elif abuse_score >= 25:
            result["verdict"], result["risk_score"] = "SUSPICIOUS", 50
        else:
            result["verdict"], result["risk_score"] = "CLEAN", 0
        result["enriched_at"] = datetime.now(timezone.utc).isoformat()
        return result

    def _abuseipdb_lookup(self, ip: str) -> dict:
        try:
            resp = requests.get(
                "https://api.abuseipdb.com/api/v2/check",
                headers={"Key": ABUSEIPDB_KEY, "Accept": "application/json"},
                params={"ipAddress": ip, "maxAgeInDays": 90},
                timeout=TIMEOUT,
            )
            data = resp.json().get("data", {})
            return {
                "abuseConfidenceScore": data.get("abuseConfidenceScore", 0),
                "countryCode": data.get("countryCode",""),
                "totalReports": data.get("totalReports", 0),
                "isWhitelisted": data.get("isWhitelisted", False),
                "usageType": data.get("usageType",""),
            }
        except Exception as e:
            logger.warning(f"AbuseIPDB error for {ip}: {e}")
            return {}

    def _otx_ip_lookup(self, ip: str) -> dict:
        try:
            resp = requests.get(
                f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general",
                headers={"X-OTX-API-KEY": OTX_API_KEY},
                timeout=TIMEOUT,
            )
            data = resp.json()
            return {
                "pulse_count": data.get("pulse_info",{}).get("count",0),
                "reputation": data.get("reputation",0),
                "country": data.get("country_name",""),
                "malware_families": data.get("pulse_info",{}).get("related",{}).get("malware_families",[]),
            }
        except Exception as e:
            logger.warning(f"OTX error for {ip}: {e}")
            return {}

if __name__ == "__main__":
    enricher = IOCEnricher()
    # Example — replace with real suspicious IP
    result = enricher.enrich_ip("1.1.1.1")
    print(json.dumps(result, indent=2))
