#!/usr/bin/env python3
"""
CloudTrail Threat Hunting Lab
Week 6 Project — Cloud Security Mentorship Programme
Kill-chain hunt across 5 MITRE ATT&CK phases mapped to CloudTrail API calls.
"""
import sys, json, argparse, logging
from datetime import datetime, timezone, timedelta
sys.path.insert(0, "../../shared")
from utils.aws_helpers import get_session, get_account_id

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
logger = logging.getLogger(__name__)

HUNT_PROFILES = {
    "recon":        {
        "events":  ["ListBuckets","DescribeInstances","ListUsers","GetCallerIdentity",
                    "ListRoles","DescribeSecurityGroups","ListFunctions20150331"],
        "mitre":   "TA0007 Discovery",
        "icon":    "🔭",
    },
    "escalation":   {
        "events":  ["CreatePolicyVersion","SetDefaultPolicyVersion","AttachUserPolicy",
                    "AttachRolePolicy","PutUserPolicy","CreateAccessKey","UpdateLoginProfile"],
        "mitre":   "TA0004 Privilege Escalation",
        "icon":    "🔺",
    },
    "exfiltration": {
        "events":  ["GetObject","GetSecretValue","ExportFindings","BatchGetSecretValue"],
        "mitre":   "TA0010 Exfiltration",
        "icon":    "📤",
    },
    "persistence":  {
        "events":  ["CreateUser","CreateFunction20150331","PutBucketReplication",
                    "CreateLoginProfile","AddUserToGroup"],
        "mitre":   "TA0003 Persistence",
        "icon":    "🕸️",
    },
    "evasion":      {
        "events":  ["StopLogging","DeleteTrail","UpdateTrail","DisableRule",
                    "DeleteFlowLogs","PutEventSelectors"],
        "mitre":   "TA0005 Defence Evasion",
        "icon":    "🫥",
    },
}


def hunt_phase(ct_client, phase_name: str, phase_def: dict,
               start_time, actor_arn: str = None) -> list:
    hits = []
    for event_name in phase_def["events"]:
        try:
            attrs = [{"AttributeKey": "EventName", "AttributeValue": event_name}]
            paginator = ct_client.get_paginator("lookup_events")
            for page in paginator.paginate(LookupAttributes=attrs, StartTime=start_time):
                for ev in page.get("Events", []):
                    raw = json.loads(ev.get("CloudTrailEvent", "{}"))
                    if raw.get("errorCode"):
                        continue
                    actor = raw.get("userIdentity", {}).get("arn", "unknown")
                    if actor_arn and actor_arn not in actor:
                        continue
                    hits.append({
                        "phase":       phase_name,
                        "mitre":       phase_def["mitre"],
                        "event_name":  event_name,
                        "actor_arn":   actor,
                        "source_ip":   raw.get("sourceIPAddress", ""),
                        "user_agent":  raw.get("userAgent", ""),
                        "event_time":  raw.get("eventTime", ""),
                        "region":      raw.get("awsRegion", ""),
                        "request":     raw.get("requestParameters", {}),
                    })
        except Exception as e:
            logger.debug(f"Query error [{phase_name}/{event_name}]: {e}")
    return hits


def run_hunt(session, actor_arn: str = None, hours: int = 24) -> dict:
    ct = session.client("cloudtrail")
    account_id = get_account_id(session)
    start = datetime.now(timezone.utc) - timedelta(hours=hours)
    timeline, phase_hits = [], {}

    logger.info(f"🔍 Starting threat hunt — account {account_id}, last {hours}h")
    for phase_name, phase_def in HUNT_PROFILES.items():
        logger.info(f"  Hunting phase: {phase_def['icon']} {phase_name.upper()}")
        hits = hunt_phase(ct, phase_name, phase_def, start, actor_arn)
        phase_hits[phase_name] = len(hits)
        timeline.extend(hits)

    timeline.sort(key=lambda x: x.get("event_time", ""))

    # Deduplicate actors seen in multiple phases (lateral movement indicator)
    multi_phase_actors = {}
    for ev in timeline:
        actor = ev["actor_arn"]
        phase = ev["phase"]
        if actor not in multi_phase_actors:
            multi_phase_actors[actor] = set()
        multi_phase_actors[actor].add(phase)

    suspects = {a: list(p) for a, p in multi_phase_actors.items() if len(p) >= 2}

    return {
        "account_id":         account_id,
        "hunt_window_hours":  hours,
        "hunt_start":         start.isoformat(),
        "hunt_end":           datetime.now(timezone.utc).isoformat(),
        "phase_hits":         phase_hits,
        "kill_chain_phases_active": sum(1 for v in phase_hits.values() if v > 0),
        "total_events":       len(timeline),
        "multi_phase_actors": suspects,
        "timeline":           timeline,
    }


def print_report(result: dict):
    print(f"\n{'='*65}")
    print(f"  🔍 THREAT HUNT RESULTS")
    print(f"  Account: {result['account_id']} | Window: {result['hunt_window_hours']}h")
    print(f"{'='*65}")
    for phase, count in result["phase_hits"].items():
        icon = HUNT_PROFILES[phase]["icon"]
        mitre = HUNT_PROFILES[phase]["mitre"]
        status = "🔴 ACTIVITY DETECTED" if count else "✅ No activity"
        print(f"  {icon} {phase.upper():<14} {status:<28} ({count} events)  [{mitre}]")

    print(f"\n  Kill-chain phases active : {result['kill_chain_phases_active']}/5")
    print(f"  Total suspicious events  : {result['total_events']}")

    if result["multi_phase_actors"]:
        print(f"\n  ⚠️  MULTI-PHASE ACTORS (HIGH PRIORITY INVESTIGATE):")
        for actor, phases in result["multi_phase_actors"].items():
            print(f"     {actor}")
            print(f"     Phases: {', '.join(phases)}")

    if result["timeline"]:
        print(f"\n  📅 Attack Timeline (first 25 events):\n")
        print(f"  {'TIME':<22} {'PHASE':<16} {'EVENT':<35} ACTOR")
        print(f"  {'-'*100}")
        for ev in result["timeline"][:25]:
            t = ev["event_time"][:19].replace("T", " ")
            print(f"  {t:<22} {ev['phase'].upper():<16} {ev['event_name']:<35} {ev['actor_arn'][-45:]}")
    print()


def main():
    parser = argparse.ArgumentParser(description="CloudTrail Threat Hunter — 5-phase kill chain")
    parser.add_argument("--profile", default=None)
    parser.add_argument("--region", default="us-east-1")
    parser.add_argument("--actor", help="Hunt specific IAM ARN or username", default=None)
    parser.add_argument("--hours", type=int, default=24, help="Look-back hours (default: 24)")
    parser.add_argument("--output", choices=["console", "json"], default="console")
    args = parser.parse_args()

    session = get_session(args.profile, args.region)
    result = run_hunt(session, args.actor, args.hours)

    if args.output == "json":
        print(json.dumps(result, indent=2, default=str))
    else:
        print_report(result)


if __name__ == "__main__":
    main()
