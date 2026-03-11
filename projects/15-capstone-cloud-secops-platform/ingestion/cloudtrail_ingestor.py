"""CloudTrail Log Ingestor — polls CloudTrail API and normalises events for detection engine."""
import sys, json, logging
from datetime import datetime, timezone, timedelta
sys.path.insert(0, "../../../shared")
from utils.aws_helpers import get_session

logger = logging.getLogger(__name__)

def ingest_recent_events(session, hours: int = 1, region: str = "us-east-1") -> list:
    """Pull recent CloudTrail events and return normalised list."""
    ct = session.client("cloudtrail", region_name=region)
    start = datetime.now(timezone.utc) - timedelta(hours=hours)
    events = []
    paginator = ct.get_paginator("lookup_events")
    for page in paginator.paginate(StartTime=start):
        for ev in page.get("Events", []):
            try:
                raw = json.loads(ev.get("CloudTrailEvent", "{}"))
                events.append(raw)
            except Exception:
                pass
    logger.info(f"Ingested {len(events)} CloudTrail events from last {hours}h")
    return events

if __name__ == "__main__":
    session = get_session()
    events = ingest_recent_events(session, hours=1)
    print(f"Ingested {len(events)} events")
    if events:
        print(json.dumps(events[0], indent=2, default=str))
