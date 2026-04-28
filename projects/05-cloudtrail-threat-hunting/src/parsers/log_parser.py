"""
CloudTrail log file parser — reads raw JSON/gzip log files from disk or S3
and returns a flat list of event dicts ready for hunting analysis.
"""
import gzip
import json
import logging
from pathlib import Path
from typing import Iterator

logger = logging.getLogger(__name__)


def iter_events_from_file(path: str | Path) -> Iterator[dict]:
    """
    Yield CloudTrail event records from a local JSON or gzipped JSON file.

    CloudTrail file format: {"Records": [...]}
    Supports both .json and .json.gz files.
    """
    p = Path(path)
    try:
        content = p.read_bytes()
        if p.suffix == '.gz' or p.name.endswith('.json.gz'):
            content = gzip.decompress(content)
        data = json.loads(content)
        records = data.get('Records', data if isinstance(data, list) else [])
        yield from records
    except (json.JSONDecodeError, gzip.BadGzipFile, OSError) as e:
        logger.warning('Could not parse %s: %s', path, e)


def load_events_from_dir(directory: str | Path,
                          recursive: bool = True) -> list[dict]:
    """
    Load all CloudTrail events from all JSON/gz files under a directory.

    Args:
        directory: Root directory to scan
        recursive: If True, search recursively (default True)

    Returns:
        Flat list of all CloudTrail event records
    """
    root = Path(directory)
    if not root.exists():
        logger.error('Directory not found: %s', directory)
        return []

    pattern = '**/*.json*' if recursive else '*.json*'
    all_events: list[dict] = []

    for path in sorted(root.glob(pattern)):
        if 'chain-of-custody' in path.name:
            continue
        events = list(iter_events_from_file(path))
        all_events.extend(events)
        logger.debug('Loaded %d events from %s', len(events), path.name)

    logger.info('Total events loaded: %d from %s', len(all_events), directory)
    return all_events


def filter_by_entity(events: list[dict],
                      ip: str | None = None,
                      user: str | None = None,
                      event_name: str | None = None) -> list[dict]:
    """
    Filter events by entity (IP address, user ARN substring, or event name).
    All provided filters are ANDed together.
    """
    filtered = events
    if ip:
        filtered = [e for e in filtered if e.get('sourceIPAddress') == ip]
    if user:
        filtered = [e for e in filtered
                    if user in e.get('userIdentity', {}).get('arn', '')]
    if event_name:
        filtered = [e for e in filtered if e.get('eventName') == event_name]
    return filtered


def extract_field(event: dict, *keys: str, default: str = '') -> str:
    """Safely extract a nested field from a CloudTrail event."""
    current = event
    for key in keys:
        if not isinstance(current, dict):
            return default
        current = current.get(key, {})
    return str(current) if current else default
