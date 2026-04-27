"""
Unit tests for UEBA Insider Threat Detection engine.
Pure Python — no AWS mocking needed.

Run:
    pip install pytest numpy pandas
    pytest tests/ -v
"""
import json
import pytest
import numpy as np
from datetime import datetime, timezone, timedelta
from unittest.mock import patch


def get_engine():
    import sys, os
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))
    from ueba.detection_engine import UEBAEngine, UserProfile, Anomaly
    return UEBAEngine, UserProfile, Anomaly


def make_events(user: str, count: int, hour: int = 10,
                service: str = 's3', ip: str = '10.0.1.5',
                region: str = 'us-east-1',
                date_offset_days: int = 0) -> list:
    """Generate synthetic CloudTrail-like events for a user."""
    base = datetime.now(timezone.utc) - timedelta(days=date_offset_days)
    return [
        {
            'eventTime': base.replace(hour=hour, minute=i % 60).isoformat(),
            'eventSource': f'{service}.amazonaws.com',
            'eventName': 'GetObject' if service == 's3' else 'DescribeInstances',
            'userIdentity': {'userName': user, 'arn': f'arn:aws:iam::123:user/{user}'},
            'sourceIPAddress': ip,
            'awsRegion': region,
        }
        for i in range(count)
    ]


# ── Baseline Building Tests ────────────────────────────────────────────────────

class TestBaselineBuilding:

    def test_baseline_computes_mean_api_count(self):
        """Baseline must compute correct mean API count per day."""
        Engine, UserProfile, Anomaly = get_engine()
        e = Engine.__new__(Engine)
        e.profiles = {}
        e._now = datetime.now(timezone.utc)

        import pandas as pd
        events = []
        for day in range(10, 1, -1):  # 10 days of data
            events += make_events('alice', count=50, date_offset_days=day)

        df = pd.DataFrame(events)
        df['eventTime'] = pd.to_datetime(df['eventTime'])
        df['userName'] = df['userIdentity'].apply(lambda x: x['userName'])
        df['hour'] = df['eventTime'].dt.hour
        df['date'] = df['eventTime'].dt.date

        e.build_baselines(df)
        assert 'alice' in e.profiles
        profile = e.profiles['alice']
        mean = np.mean(profile.daily_api_counts)
        assert 45 <= mean <= 55, f'Expected mean ~50, got {mean}'

    def test_baseline_captures_usual_hours(self):
        """Baseline must identify the user's normal working hours."""
        Engine, UserProfile, Anomaly = get_engine()
        e = Engine.__new__(Engine)
        e.profiles = {}
        e._now = datetime.now(timezone.utc)

        import pandas as pd
        events = []
        for day in range(10, 1, -1):
            events += make_events('bob', count=20, hour=14, date_offset_days=day)

        df = pd.DataFrame(events)
        df['eventTime'] = pd.to_datetime(df['eventTime'])
        df['userName'] = df['userIdentity'].apply(lambda x: x['userName'])
        df['hour'] = df['eventTime'].dt.hour
        df['date'] = df['eventTime'].dt.date

        e.build_baselines(df)
        assert 14 in e.profiles['bob'].usual_hours

    def test_baseline_stores_seen_ips(self):
        """Baseline must record all source IPs seen during the baseline period."""
        Engine, UserProfile, Anomaly = get_engine()
        e = Engine.__new__(Engine)
        e.profiles = {}
        e._now = datetime.now(timezone.utc)

        import pandas as pd
        events = make_events('carol', count=10, ip='10.0.0.5', date_offset_days=5)
        df = pd.DataFrame(events)
        df['eventTime'] = pd.to_datetime(df['eventTime'])
        df['userName'] = df['userIdentity'].apply(lambda x: x['userName'])
        df['hour'] = df['eventTime'].dt.hour
        df['date'] = df['eventTime'].dt.date

        e.build_baselines(df)
        assert '10.0.0.5' in e.profiles['carol'].seen_ips


# ── Anomaly Detection Tests ────────────────────────────────────────────────────

class TestAnomalyDetection:

    def _build_engine_with_profile(self, username: str,
                                    daily_counts: list,
                                    usual_hours: set = None,
                                    seen_ips: set = None,
                                    seen_regions: set = None,
                                    seen_services: set = None):
        Engine, UserProfile, Anomaly = get_engine()
        e = Engine.__new__(Engine)
        e.profiles = {}
        e.anomalies = []
        e._now = datetime.now(timezone.utc)

        profile = UserProfile(username=username)
        profile.daily_api_counts = daily_counts
        profile.usual_hours = usual_hours or {9, 10, 11, 12, 13, 14, 15, 16, 17}
        profile.seen_ips = seen_ips or {'10.0.0.1'}
        profile.seen_regions = seen_regions or {'us-east-1'}
        profile.seen_services = seen_services or {'s3', 'ec2', 'iam'}
        e.profiles[username] = profile
        return e, Engine, UserProfile, Anomaly

    def test_volume_spike_detected(self):
        """API call volume > 3 standard deviations must be flagged."""
        e, *_ = self._build_engine_with_profile(
            'attacker',
            daily_counts=[50] * 21  # baseline: 50/day
        )
        import pandas as pd
        # Today: 1000 calls — clearly anomalous
        today_events = make_events('attacker', count=1000, date_offset_days=0)
        df = pd.DataFrame(today_events)
        df['eventTime'] = pd.to_datetime(df['eventTime'])
        df['userName'] = df['userIdentity'].apply(lambda x: x['userName'])
        df['hour'] = df['eventTime'].dt.hour
        df['date'] = df['eventTime'].dt.date

        e.detect_anomalies(df)
        volume_anomalies = [a for a in e.anomalies
                            if a.anomaly_type == 'API_VOLUME_SPIKE']
        assert len(volume_anomalies) >= 1
        assert all(a.severity in ('HIGH', 'CRITICAL') for a in volume_anomalies)

    def test_normal_volume_not_flagged(self):
        """API call volume within 3σ must not be flagged."""
        e, *_ = self._build_engine_with_profile(
            'normal-user',
            daily_counts=[50] * 21
        )
        import pandas as pd
        today_events = make_events('normal-user', count=52, date_offset_days=0)
        df = pd.DataFrame(today_events)
        df['eventTime'] = pd.to_datetime(df['eventTime'])
        df['userName'] = df['userIdentity'].apply(lambda x: x['userName'])
        df['hour'] = df['eventTime'].dt.hour
        df['date'] = df['eventTime'].dt.date

        e.detect_anomalies(df)
        volume_anomalies = [a for a in e.anomalies
                            if a.anomaly_type == 'API_VOLUME_SPIKE'
                            and a.user == 'normal-user']
        assert len(volume_anomalies) == 0

    def test_off_hours_access_detected(self):
        """API calls outside normal hours must be flagged."""
        e, *_ = self._build_engine_with_profile(
            'night-owl',
            daily_counts=[50] * 21,
            usual_hours={9, 10, 11, 12, 13, 14, 15, 16, 17}
        )
        import pandas as pd
        # Calls at 2am — outside normal hours
        events = make_events('night-owl', count=20, hour=2, date_offset_days=0)
        df = pd.DataFrame(events)
        df['eventTime'] = pd.to_datetime(df['eventTime'])
        df['userName'] = df['userIdentity'].apply(lambda x: x['userName'])
        df['hour'] = df['eventTime'].dt.hour
        df['date'] = df['eventTime'].dt.date

        e.detect_anomalies(df)
        off_hours = [a for a in e.anomalies if a.anomaly_type == 'OFF_HOURS_ACCESS']
        assert len(off_hours) >= 1

    def test_new_ip_detected(self):
        """API call from an IP not in baseline must produce anomaly."""
        e, *_ = self._build_engine_with_profile(
            'traveller',
            daily_counts=[50] * 21,
            seen_ips={'10.0.0.1'}
        )
        import pandas as pd
        # Calls from a new IP
        events = make_events('traveller', count=10, ip='203.0.113.99', date_offset_days=0)
        df = pd.DataFrame(events)
        df['eventTime'] = pd.to_datetime(df['eventTime'])
        df['userName'] = df['userIdentity'].apply(lambda x: x['userName'])
        df['hour'] = df['eventTime'].dt.hour
        df['date'] = df['eventTime'].dt.date

        e.detect_anomalies(df)
        new_ip_anomalies = [a for a in e.anomalies if a.anomaly_type == 'NEW_SOURCE_IP']
        assert len(new_ip_anomalies) >= 1

    def test_new_region_access_detected(self):
        """API calls from an unusual region must be flagged."""
        e, *_ = self._build_engine_with_profile(
            'region-hopper',
            daily_counts=[50] * 21,
            seen_regions={'us-east-1'}
        )
        import pandas as pd
        events = make_events('region-hopper', count=5, region='ap-northeast-1', date_offset_days=0)
        df = pd.DataFrame(events)
        df['eventTime'] = pd.to_datetime(df['eventTime'])
        df['userName'] = df['userIdentity'].apply(lambda x: x['userName'])
        df['hour'] = df['eventTime'].dt.hour
        df['date'] = df['eventTime'].dt.date

        e.detect_anomalies(df)
        region_anomalies = [a for a in e.anomalies if a.anomaly_type == 'NEW_REGION']
        assert len(region_anomalies) >= 1


# ── Risk Scoring Tests ─────────────────────────────────────────────────────────

class TestRiskScoring:

    def test_risk_score_increases_with_anomalies(self):
        """More anomalies must produce a higher risk score."""
        Engine, UserProfile, Anomaly = get_engine()
        e = Engine.__new__(Engine)
        e.anomalies = [
            Anomaly('alice', '2024-01-15', 'API_VOLUME_SPIKE', 'HIGH', 'detail1', 3.5, 30),
            Anomaly('alice', '2024-01-15', 'NEW_SOURCE_IP', 'MEDIUM', 'detail2', 0, 20),
            Anomaly('alice', '2024-01-15', 'NEW_REGION', 'MEDIUM', 'detail3', 0, 25),
        ]
        e.risk_scores = {}
        e.calculate_risk_scores()
        assert e.risk_scores.get('alice', 0) >= 50

    def test_risk_score_capped_at_100(self):
        """Risk score must never exceed 100."""
        Engine, UserProfile, Anomaly = get_engine()
        e = Engine.__new__(Engine)
        e.anomalies = [
            Anomaly('maxed', '2024-01-15', 'API_VOLUME_SPIKE', 'CRITICAL', '', 5.0, 50),
            Anomaly('maxed', '2024-01-15', 'NEW_REGION', 'HIGH', '', 0, 50),
            Anomaly('maxed', '2024-01-15', 'NEW_SOURCE_IP', 'HIGH', '', 0, 50),
        ]
        e.risk_scores = {}
        e.calculate_risk_scores()
        assert e.risk_scores.get('maxed', 0) <= 100

    def test_user_with_no_anomalies_has_zero_risk(self):
        """User with no anomalies must have risk score of 0."""
        Engine, UserProfile, Anomaly = get_engine()
        e = Engine.__new__(Engine)
        e.anomalies = []
        e.risk_scores = {}
        e.calculate_risk_scores()
        assert e.risk_scores.get('clean-user', 0) == 0


# ── Statistical Helper Tests ───────────────────────────────────────────────────

class TestSigmaDetection:

    def test_value_above_3_sigma_is_anomalous(self):
        """Value > 3σ above mean must be detected as anomalous."""
        Engine, *_ = get_engine()
        e = Engine.__new__(Engine)
        baseline = [50.0] * 30
        is_anom, z = e._is_sigma_anomaly(200.0, baseline)
        assert is_anom is True
        assert z > 3

    def test_value_within_2_sigma_not_anomalous(self):
        """Value within 2σ must not be anomalous."""
        Engine, *_ = get_engine()
        e = Engine.__new__(Engine)
        baseline = [50.0, 52.0, 48.0, 51.0, 49.0] * 5
        is_anom, _ = e._is_sigma_anomaly(53.0, baseline)
        assert is_anom is False

    def test_insufficient_baseline_not_anomalous(self):
        """Fewer than 5 baseline points must not flag as anomalous."""
        Engine, *_ = get_engine()
        e = Engine.__new__(Engine)
        is_anom, _ = e._is_sigma_anomaly(1000.0, [50.0, 50.0])
        assert is_anom is False
