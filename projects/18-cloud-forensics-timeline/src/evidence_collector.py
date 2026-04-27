"""
Cloud Forensic Evidence Collector — with chain of custody.
Collects CloudTrail events and VPC Flow Logs for incident response.
"""
import gzip
import hashlib
import json
import time
from datetime import datetime, timezone, timedelta
from dataclasses import dataclass, asdict, field
from pathlib import Path
from typing import Optional

import boto3


@dataclass
class EvidenceItem:
    source: str              # cloudtrail | vpc_flow | s3_access | elb_access
    original_location: str   # s3://bucket/key or service identifier
    local_path: str
    sha256: str
    size_bytes: int
    collected_at: str
    collector_identity: str
    event_count: int = 0


class ForensicEvidenceCollector:

    def __init__(self, incident_id: str, region: str = 'us-east-1',
                 output_dir: str = 'evidence'):
        self.incident_id = incident_id
        self.region = region
        self.output_dir = Path(output_dir) / incident_id
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.s3 = boto3.client('s3', region_name=region)
        self.sts = boto3.client('sts', region_name=region)
        self.evidence_manifest: list[EvidenceItem] = []
        self._identity = self._get_collector_identity()

    def _get_collector_identity(self) -> str:
        resp = self.sts.get_caller_identity()
        return f"{resp['UserId']}@{resp['Account']}"

    def _sha256(self, path: Path) -> str:
        h = hashlib.sha256()
        with open(path, 'rb') as f:
            for chunk in iter(lambda: f.read(65536), b''):
                h.update(chunk)
        return h.hexdigest()

    def _download_s3_file(self, bucket: str, key: str,
                           local_name: str) -> Path:
        local = self.output_dir / local_name
        local.parent.mkdir(parents=True, exist_ok=True)
        self.s3.download_file(bucket, key, str(local))
        return local

    def collect_cloudtrail_s3(self, bucket: str, prefix: str,
                               start: datetime, end: datetime) -> int:
        """
        Collect CloudTrail logs from S3 for the given time window.
        Returns number of files collected.
        """
        ct_dir = self.output_dir / 'cloudtrail'
        ct_dir.mkdir(exist_ok=True)
        collected = 0

        paginator = self.s3.get_paginator('list_objects_v2')
        for page in paginator.paginate(Bucket=bucket, Prefix=prefix):
            for obj in page.get('Contents', []):
                key = obj['Key']
                # CloudTrail key format: PREFIX/AWSLogs/ACCOUNT/CloudTrail/REGION/YYYY/MM/DD/
                try:
                    parts = key.split('/')
                    # Find the date parts in the key
                    date_str = None
                    for i, part in enumerate(parts):
                        if len(part) == 4 and part.isdigit():  # year
                            date_str = f'{part}-{parts[i+1]}-{parts[i+2]}'
                            break
                    if date_str:
                        file_date = datetime.strptime(date_str, '%Y-%m-%d').replace(tzinfo=timezone.utc)
                        if not (start.date() <= file_date.date() <= end.date()):
                            continue
                except (ValueError, IndexError):
                    pass  # Include file if we can't parse date

                safe_name = key.replace('/', '_')
                local = self._download_s3_file(bucket, key, f'cloudtrail/{safe_name}')
                sha = self._sha256(local)

                # Count events in the file
                event_count = self._count_cloudtrail_events(local)

                self.evidence_manifest.append(EvidenceItem(
                    source='cloudtrail',
                    original_location=f's3://{bucket}/{key}',
                    local_path=str(local),
                    sha256=sha,
                    size_bytes=obj['Size'],
                    collected_at=datetime.now(timezone.utc).isoformat(),
                    collector_identity=self._identity,
                    event_count=event_count,
                ))
                collected += 1

        print(f'[+] CloudTrail: collected {collected} files')
        return collected

    def _count_cloudtrail_events(self, path: Path) -> int:
        try:
            content = path.read_bytes()
            if path.suffix == '.gz':
                content = gzip.decompress(content)
            data = json.loads(content)
            return len(data.get('Records', []))
        except Exception:
            return 0

    def save_chain_of_custody(self) -> Path:
        """Write the chain of custody document."""
        coc = {
            'incident_id': self.incident_id,
            'collection_started': datetime.now(timezone.utc).isoformat(),
            'collector_identity': self._identity,
            'region': self.region,
            'total_files': len(self.evidence_manifest),
            'total_bytes': sum(e.size_bytes for e in self.evidence_manifest),
            'total_events': sum(e.event_count for e in self.evidence_manifest),
            'evidence': [asdict(e) for e in self.evidence_manifest],
        }
        coc_path = self.output_dir / 'chain-of-custody.json'
        coc_path.write_text(json.dumps(coc, indent=2))
        print(f'[+] Chain of custody saved → {coc_path}')
        return coc_path
