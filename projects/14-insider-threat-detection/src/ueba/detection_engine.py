"""
Insider Threat Detection System — UEBA Engine
Week 16 Project — Cloud Security Mentorship Programme

Builds behaviour baselines per user and detects anomalies using
statistical methods (z-score, IQR) mapped to insider threat TTPs.
"""
import json
import math
import statistics
import logging
from collections import defaultdict
from datetime import datetime, timezone, timedelta
from typing import List, Dict, Any, Optional

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")


# ─── RISK WEIGHTS ─────────────────────────────────────────────────────────────
RISK_INDICATORS = {
    "volume_anomaly":        {"weight": 20, "description": "Unusual volume of API calls"},
    "after_hours_access":    {"weight": 25, "description": "Access outside business hours"},
    "new_resource_access":   {"weight": 30, "description": "Accessed resource never used before"},
    "bulk_s3_download":      {"weight": 35, "description": "Mass S3 object downloads"},
    "sensitive_service":     {"weight": 20, "description": "Accessed sensitive service (secrets, KMS)"},
    "cross_account_access":  {"weight": 25, "description": "Cross-account AssumeRole"},
    "key_creation_anomaly":  {"weight": 40, "description": "Access key created outside normal pattern"},
    "failed_then_success":   {"weight": 30, "description": "Repeated failures followed by success"},
    "off_region_activity":   {"weight": 15, "description": "Activity in unusual AWS region"},
    "weekend_admin_action":  {"weight": 35, "description": "Admin IAM action on weekend"},
}

SENSITIVE_SERVICES = {
    "secretsmanager.amazonaws.com",
    "kms.amazonaws.com",
    "ssm.amazonaws.com",
    "iam.amazonaws.com",
}

BUSINESS_HOURS = (7, 20)   # 07:00 - 20:00
BUSINESS_DAYS = {0, 1, 2, 3, 4}  # Mon-Fri


class UserProfile:
    """Stores a user's baseline behaviour metrics."""

    def __init__(self, user_arn: str):
        self.user_arn = user_arn
        self.username = user_arn.split("/")[-1]
        self.daily_api_calls: List[int] = []
        self.hourly_distribution: Dict[int, int] = defaultdict(int)
        self.known_services: set = set()
        self.known_resources: set = set()
        self.known_regions: set = set()
        self.known_source_ips: set = set()
        self.s3_daily_downloads: List[int] = []
        self.total_events: int = 0
        self.baseline_days: int = 0

    def add_day_data(self, day_events: List[Dict]):
        """Add one day's events to the baseline."""
        self.daily_api_calls.append(len(day_events))
        self.baseline_days += 1
        self.total_events += len(day_events)

        for event in day_events:
            hour = event.get("hour", 12)
            self.hourly_distribution[hour] += 1
            self.known_services.add(event.get("eventSource", ""))
            self.known_resources.add(event.get("resource", ""))
            self.known_regions.add(event.get("awsRegion", ""))
            self.known_source_ips.add(event.get("sourceIPAddress", ""))
            if event.get("eventSource") == "s3.amazonaws.com":
                if event.get("eventName") == "GetObject":
                    s3_count = event.get("s3_object_count", 1)
                    self.s3_daily_downloads.append(s3_count)

    def avg_daily_calls(self) -> float:
        return statistics.mean(self.daily_api_calls) if self.daily_api_calls else 0

    def stdev_daily_calls(self) -> float:
        return statistics.stdev(self.daily_api_calls) if len(self.daily_api_calls) > 1 else 1.0

    def z_score(self, value: float) -> float:
        """Calculate z-score for a value vs daily call baseline."""
        mean = self.avg_daily_calls()
        stdev = self.stdev_daily_calls()
        if stdev == 0:
            return 0.0
        return (value - mean) / stdev

    def typical_hours(self) -> set:
        """Return hours with > 5% of the user's activity."""
        if not self.hourly_distribution:
            return set(range(8, 18))  # Default business hours
        total = sum(self.hourly_distribution.values())
        return {h for h, c in self.hourly_distribution.items()
                if c / total > 0.05}

    def to_dict(self) -> Dict:
        return {
            "user_arn": self.user_arn,
            "username": self.username,
            "baseline_days": self.baseline_days,
            "avg_daily_calls": round(self.avg_daily_calls(), 1),
            "stdev_daily_calls": round(self.stdev_daily_calls(), 1),
            "known_services_count": len(self.known_services),
            "known_regions": list(self.known_regions),
            "typical_hours": sorted(self.typical_hours()),
        }


class InsiderThreatDetector:
    """
    UEBA engine — builds baselines and detects insider threat indicators.
    """

    def __init__(self, baseline_days: int = 30, risk_threshold: int = 50):
        self.profiles: Dict[str, UserProfile] = {}
        self.baseline_days = baseline_days
        self.risk_threshold = risk_threshold

    def build_baselines(self, historical_events: List[Dict]) -> None:
        """Build per-user behaviour baselines from historical CloudTrail events."""
        # Group events by user and day
        user_day_events: Dict[str, Dict[str, List]] = defaultdict(lambda: defaultdict(list))

        for event in historical_events:
            user_arn = event.get("userIdentity", {}).get("arn", "unknown")
            event_time = event.get("eventTime", "")
            try:
                dt = datetime.fromisoformat(event_time.replace("Z", "+00:00"))
                day_key = dt.strftime("%Y-%m-%d")
                event["hour"] = dt.hour
                event["day_of_week"] = dt.weekday()
            except Exception:
                day_key = "unknown"
                event["hour"] = 12
                event["day_of_week"] = 0

            user_day_events[user_arn][day_key].append(event)

        # Build profile for each user
        for user_arn, day_data in user_day_events.items():
            profile = UserProfile(user_arn)
            for _day, events in sorted(day_data.items()):
                profile.add_day_data(events)
            self.profiles[user_arn] = profile

        logger.info(f"Built baselines for {len(self.profiles)} users "
                    f"({sum(p.baseline_days for p in self.profiles.values())} user-days)")

    def analyse_events(self, current_events: List[Dict],
                       analysis_window_hours: int = 24) -> List[Dict]:
        """Analyse current events against baselines to find anomalies."""
        alerts = []
        user_current: Dict[str, List] = defaultdict(list)

        for event in current_events:
            user_arn = event.get("userIdentity", {}).get("arn", "unknown")
            user_current[user_arn].append(event)

        for user_arn, events in user_current.items():
            profile = self.profiles.get(user_arn)
            risk_score = 0
            triggered_indicators = []

            # ── Indicator 1: Volume anomaly ──────────────────────────────────
            event_count = len(events)
            if profile:
                z = profile.z_score(event_count)
                if z > 3.0:  # More than 3 std deviations above baseline
                    risk_score += RISK_INDICATORS["volume_anomaly"]["weight"]
                    triggered_indicators.append({
                        "indicator": "volume_anomaly",
                        "details": f"{event_count} events (baseline avg: "
                                   f"{profile.avg_daily_calls():.0f}, z-score: {z:.1f})",
                        "risk_weight": RISK_INDICATORS["volume_anomaly"]["weight"],
                    })

            # ── Indicator 2: After-hours access ─────────────────────────────
            after_hours = [e for e in events
                           if e.get("hour", 12) < BUSINESS_HOURS[0]
                           or e.get("hour", 12) >= BUSINESS_HOURS[1]
                           or e.get("day_of_week", 0) not in BUSINESS_DAYS]
            if len(after_hours) > 5:
                risk_score += RISK_INDICATORS["after_hours_access"]["weight"]
                triggered_indicators.append({
                    "indicator": "after_hours_access",
                    "details": f"{len(after_hours)} events outside business hours",
                    "risk_weight": RISK_INDICATORS["after_hours_access"]["weight"],
                })

            # ── Indicator 3: New resource access ────────────────────────────
            if profile:
                new_resources = set()
                for event in events:
                    resource = event.get("resource", "")
                    if resource and resource not in profile.known_resources:
                        new_resources.add(resource)
                if len(new_resources) > 5:
                    risk_score += RISK_INDICATORS["new_resource_access"]["weight"]
                    triggered_indicators.append({
                        "indicator": "new_resource_access",
                        "details": f"{len(new_resources)} previously-unseen resources accessed",
                        "risk_weight": RISK_INDICATORS["new_resource_access"]["weight"],
                    })

            # ── Indicator 4: Bulk S3 downloads ──────────────────────────────
            s3_downloads = sum(
                1 for e in events
                if e.get("eventSource") == "s3.amazonaws.com"
                and e.get("eventName") == "GetObject"
            )
            if s3_downloads > 100:
                risk_score += RISK_INDICATORS["bulk_s3_download"]["weight"]
                triggered_indicators.append({
                    "indicator": "bulk_s3_download",
                    "details": f"{s3_downloads} S3 GetObject calls in {analysis_window_hours}h",
                    "risk_weight": RISK_INDICATORS["bulk_s3_download"]["weight"],
                })

            # ── Indicator 5: Sensitive service access ────────────────────────
            sensitive_hits = [e for e in events
                              if e.get("eventSource") in SENSITIVE_SERVICES]
            if len(sensitive_hits) > 10:
                risk_score += RISK_INDICATORS["sensitive_service"]["weight"]
                triggered_indicators.append({
                    "indicator": "sensitive_service",
                    "details": f"{len(sensitive_hits)} accesses to secrets/KMS/IAM",
                    "risk_weight": RISK_INDICATORS["sensitive_service"]["weight"],
                })

            # ── Indicator 6: Weekend IAM admin actions ────────────────────────
            weekend_admin = [
                e for e in events
                if e.get("day_of_week") in (5, 6)  # Saturday, Sunday
                and e.get("eventSource") == "iam.amazonaws.com"
                and e.get("eventName", "").startswith(
                    ("Create", "Attach", "Put", "Update", "Delete"))
            ]
            if weekend_admin:
                risk_score += RISK_INDICATORS["weekend_admin_action"]["weight"]
                triggered_indicators.append({
                    "indicator": "weekend_admin_action",
                    "details": f"{len(weekend_admin)} IAM admin actions on weekend",
                    "risk_weight": RISK_INDICATORS["weekend_admin_action"]["weight"],
                })

            # ── Generate alert if risk threshold exceeded ─────────────────────
            if risk_score >= self.risk_threshold and triggered_indicators:
                severity = ("CRITICAL" if risk_score >= 80 else
                            "HIGH" if risk_score >= 60 else "MEDIUM")
                alerts.append({
                    "user_arn": user_arn,
                    "username": user_arn.split("/")[-1],
                    "risk_score": risk_score,
                    "severity": severity,
                    "event_count": event_count,
                    "analysis_period_hours": analysis_window_hours,
                    "triggered_indicators": triggered_indicators,
                    "baseline_available": profile is not None,
                    "baseline_summary": profile.to_dict() if profile else None,
                    "detected_at": datetime.now(timezone.utc).isoformat(),
                    "mitre_tactics": ["TA0009 Collection", "TA0010 Exfiltration",
                                      "TA0006 Credential Access"],
                    "recommended_actions": [
                        "Review user's recent activity in CloudTrail",
                        "Check HR system for resignation or disciplinary action",
                        "Suspend user account pending investigation if risk > 80",
                        "Preserve evidence: export logs to forensic bucket",
                    ],
                })

        return sorted(alerts, key=lambda x: -x["risk_score"])


def generate_risk_report(alerts: List[Dict]) -> str:
    """Generate a Markdown risk report for the analysis period."""
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    report = f"# 🔍 Insider Threat Risk Report\n\n**Generated:** {now}\n\n"

    if not alerts:
        report += "## ✅ No High-Risk Users Detected\n\n"
        report += "No users exceeded the risk threshold in this analysis period.\n"
        return report

    report += f"## ⚠️ {len(alerts)} High-Risk User(s) Detected\n\n"
    report += "| Rank | User | Risk Score | Severity | Top Indicator |\n"
    report += "|------|------|-----------|----------|---------------|\n"

    for i, alert in enumerate(alerts[:10], 1):
        top_ind = alert["triggered_indicators"][0]["indicator"] if alert["triggered_indicators"] else "N/A"
        report += (f"| {i} | `{alert['username']}` | **{alert['risk_score']}** | "
                   f"{alert['severity']} | {top_ind} |\n")

    report += "\n---\n\n## Detailed Findings\n\n"
    for alert in alerts:
        report += f"### 👤 {alert['username']}\n\n"
        report += f"- **Risk Score:** {alert['risk_score']}/100\n"
        report += f"- **Severity:** {alert['severity']}\n"
        report += f"- **Events Analysed:** {alert['event_count']}\n\n"
        report += "**Triggered Indicators:**\n\n"
        for ind in alert["triggered_indicators"]:
            report += f"- `{ind['indicator']}` (+{ind['risk_weight']}) — {ind['details']}\n"
        report += "\n**Recommended Actions:**\n\n"
        for action in alert["recommended_actions"]:
            report += f"- {action}\n"
        report += "\n---\n\n"

    report += "\n\n> ⚠️ **Privacy Notice:** This monitoring system operates under "
    report += "organisation policy XYZ. All investigations must follow HR and legal protocols."
    return report


if __name__ == "__main__":
    # Demo usage with simulated data
    import random
    random.seed(99)

    def make_event(user: str, hour: int, day_offset: int,
                   service: str = "s3.amazonaws.com",
                   event_name: str = "GetObject") -> Dict:
        dt = datetime.now(timezone.utc) - timedelta(days=day_offset)
        dt = dt.replace(hour=hour)
        return {
            "userIdentity": {"arn": f"arn:aws:iam::123456789012:user/{user}"},
            "eventSource": service,
            "eventName": event_name,
            "eventTime": dt.isoformat(),
            "awsRegion": "us-east-1",
            "sourceIPAddress": f"10.0.{random.randint(1, 254)}.{random.randint(1, 254)}",
            "resource": f"arn:aws:s3:::bucket-{random.randint(1, 5)}",
            "hour": hour,
            "day_of_week": dt.weekday(),
        }

    # Generate 30 days of baseline
    baseline = []
    for user in ["alice", "bob", "charlie"]:
        for day in range(30, 0, -1):
            for _ in range(random.randint(10, 30)):
                baseline.append(make_event(user, random.randint(8, 17), day))

    # Generate "suspicious" current day for alice (bulk download at night)
    current = []
    for _ in range(250):  # Unusual volume
        current.append(make_event("alice", random.choice([2, 3, 4]), 0))  # After hours
    for _ in range(20):
        current.append(make_event("alice", 14, 0,
                                  service="iam.amazonaws.com", event_name="CreateAccessKey"))
    # Normal activity for bob
    for _ in range(15):
        current.append(make_event("bob", random.randint(9, 17), 0))

    detector = InsiderThreatDetector(risk_threshold=40)
    detector.build_baselines(baseline)
    alerts = detector.analyse_events(current)

    report = generate_risk_report(alerts)
    print(report)

    if alerts:
        print(f"\n🚨 {len(alerts)} risk alert(s) generated")
        for a in alerts:
            print(f"  [{a['severity']}] {a['username']}: score={a['risk_score']}")
