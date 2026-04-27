"""Tests for the forensic timeline builder."""
import pytest
from datetime import datetime, timezone, timedelta

import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))
from timeline_builder import (
    build_timeline, get_mitre_tactic, detect_kill_chain_stages,
    build_actor_timeline, generate_narrative, MITRE_MAP
)


def make_event(event_name: str, ts: str = '2024-01-15T03:00:00Z',
               actor: str = 'arn:aws:iam::123:user/attacker',
               ip: str = '1.2.3.4') -> dict:
    return {
        'eventName': event_name,
        'eventTime': ts,
        'userIdentity': {'type': 'IAMUser', 'arn': actor, 'userName': 'attacker'},
        'sourceIPAddress': ip,
        'awsRegion': 'us-east-1',
        'eventSource': 'iam.amazonaws.com',
        'requestParameters': {},
    }


class TestMITREMapping:

    def test_known_events_have_mitre(self):
        """Well-known escalation events must have MITRE mappings."""
        required = ['DeleteTrail', 'StopLogging', 'CreateUser',
                    'CreateAccessKey', 'GetObject', 'AttachUserPolicy']
        for event_name in required:
            tactic = get_mitre_tactic(event_name)
            assert tactic != '', f'{event_name} has no MITRE tactic mapping'

    def test_unknown_event_returns_empty_string(self):
        assert get_mitre_tactic('SomeRandomApiCall') == ''

    def test_root_api_call_discovery_tactic(self):
        assert get_mitre_tactic('GetCallerIdentity') == 'Discovery'

    def test_delete_trail_defense_evasion(self):
        assert get_mitre_tactic('DeleteTrail') == 'Defense Evasion'

    def test_create_user_persistence(self):
        assert get_mitre_tactic('CreateUser') == 'Persistence'

    def test_mitre_ids_format(self):
        """All MITRE technique IDs must match T-number format."""
        import re
        pattern = re.compile(r'^T\d{4}(\.\d{3})?$')
        for event_name, (tid, _, _) in MITRE_MAP.items():
            if tid:
                assert pattern.match(tid), f'{event_name}: invalid MITRE ID {tid}'


class TestTimelineBuilding:

    def test_timeline_sorted_chronologically(self):
        events = [
            make_event('CreateUser', '2024-01-15T03:10:00Z'),
            make_event('GetCallerIdentity', '2024-01-15T03:00:00Z'),
            make_event('AttachUserPolicy', '2024-01-15T03:05:00Z'),
        ]
        df = build_timeline(events)
        times = df['event_time'].tolist()
        assert times == sorted(times), 'Timeline must be sorted chronologically'

    def test_ip_filter_applied(self):
        events = [
            make_event('GetCallerIdentity', ip='1.2.3.4'),
            make_event('CreateUser', ip='5.6.7.8'),
        ]
        df = build_timeline(events, entity_filter={'ip': '1.2.3.4'})
        assert len(df) == 1
        assert df.iloc[0]['event_name'] == 'GetCallerIdentity'

    def test_user_filter_applied(self):
        events = [
            make_event('GetCallerIdentity', actor='arn:aws:iam::123:user/alice'),
            make_event('CreateUser', actor='arn:aws:iam::123:user/bob'),
        ]
        df = build_timeline(events, entity_filter={'user': 'alice'})
        assert len(df) == 1
        assert 'alice' in df.iloc[0]['actor_arn']

    def test_empty_events_returns_empty_df(self):
        df = build_timeline([])
        assert df.empty

    def test_mitre_annotations_present(self):
        events = [make_event('DeleteTrail')]
        df = build_timeline(events)
        row = df.iloc[0]
        assert row['mitre_id'] == 'T1562.008'
        assert row['mitre_tactic'] == 'Defense Evasion'

    def test_unknown_event_has_empty_mitre(self):
        events = [make_event('DescribeVpcs')]
        df = build_timeline(events)
        row = df.iloc[0]
        assert row['mitre_id'] == ''


class TestKillChainDetection:

    def test_multi_stage_attack_detected(self):
        events = [
            make_event('GetCallerIdentity'),   # Discovery
            make_event('CreateUser'),           # Persistence
            make_event('AttachUserPolicy'),     # Privilege Escalation
            make_event('GetObject'),            # Collection
        ]
        stages = detect_kill_chain_stages(events)
        assert 'Discovery' in stages
        assert 'Persistence' in stages
        assert 'Privilege Escalation' in stages
        assert 'Collection' in stages

    def test_stages_in_tactic_order(self):
        """Detected stages must follow the standard kill chain order."""
        events = [
            make_event('GetObject'),           # Collection
            make_event('GetCallerIdentity'),   # Discovery
        ]
        stages = detect_kill_chain_stages(events)
        discovery_idx = stages.index('Discovery')
        collection_idx = stages.index('Collection')
        assert discovery_idx < collection_idx

    def test_single_event_one_stage(self):
        events = [make_event('DeleteTrail')]
        stages = detect_kill_chain_stages(events)
        assert stages == ['Defense Evasion']

    def test_no_known_events_empty_stages(self):
        events = [make_event('DescribeVpcs'), make_event('ListVpcs')]
        stages = detect_kill_chain_stages(events)
        assert len(stages) == 0


class TestActorTimeline:

    def test_actor_timeline_filters_by_arn(self):
        events = [
            make_event('GetCallerIdentity', actor='arn:aws:iam::123:user/alice'),
            make_event('CreateUser', actor='arn:aws:iam::123:user/bob'),
            make_event('ListBuckets', actor='arn:aws:iam::123:user/alice'),
        ]
        timeline = build_actor_timeline(events, 'alice')
        assert len(timeline) == 2
        assert all('alice' in e['userIdentity']['arn'] for e in timeline)

    def test_actor_timeline_sorted(self):
        events = [
            make_event('CreateUser', ts='2024-01-15T03:10:00Z',
                        actor='arn:aws:iam::123:user/alice'),
            make_event('GetCallerIdentity', ts='2024-01-15T03:00:00Z',
                        actor='arn:aws:iam::123:user/alice'),
        ]
        timeline = build_actor_timeline(events, 'alice')
        times = [e['eventTime'] for e in timeline]
        assert times == sorted(times)


class TestNarrativeGeneration:

    def test_narrative_has_required_sections(self):
        import pandas as pd
        events = [
            make_event('GetCallerIdentity', '2024-01-15T03:00:00Z'),
            make_event('DeleteTrail', '2024-01-15T03:05:00Z'),
        ]
        df = build_timeline(events)
        narrative = generate_narrative(df, 'IR-2024-001')
        assert '# Incident Timeline' in narrative
        assert 'IR-2024-001' in narrative
        assert 'MITRE' in narrative

    def test_empty_df_returns_no_events_message(self):
        import pandas as pd
        narrative = generate_narrative(pd.DataFrame(), 'IR-2024-002')
        assert 'No events found' in narrative
