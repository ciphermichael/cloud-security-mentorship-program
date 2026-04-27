"""
Unit tests for GitHub Security Monitor.
Uses unittest.mock — no live GitHub token needed.

Run:
    pip install pytest pytest-mock
    pytest tests/ -v
"""
import json
import pytest
from unittest.mock import MagicMock, patch, PropertyMock


def get_monitor():
    import sys, os
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))
    from monitor import GitHubSecurityMonitor, SecurityFinding
    return GitHubSecurityMonitor, SecurityFinding


def make_mock_org(two_fa: bool = True, outside_collabs: list = None) -> MagicMock:
    org = MagicMock()
    org.login = 'test-org'
    org.two_factor_requirement_enabled = two_fa
    org.get_outside_collaborators.return_value = outside_collabs or []
    org.get_repos.return_value = []
    return org


def make_mock_repo(name: str = 'test-repo',
                   protected: bool = True,
                   secret_alerts: list = None,
                   write_token_perms: bool = False) -> MagicMock:
    repo = MagicMock()
    repo.name = name
    repo.private = True

    branch = MagicMock()
    if protected:
        protection = MagicMock()
        protection.required_pull_request_reviews = MagicMock()
        protection.required_status_checks = [MagicMock()]
        branch.get_protection.return_value = protection
    else:
        from github import GithubException
        branch.get_protection.side_effect = GithubException(404, 'Not protected', {})

    repo.get_branch.return_value = branch
    repo.get_secret_scanning_alerts.return_value = secret_alerts or []
    repo.get_workflow_run_default_permissions.return_value = {
        'default_workflow_permissions': 'write' if write_token_perms else 'read'
    }
    return repo


# ── Org-Level Tests ───────────────────────────────────────────────────────────

class TestOrgSettings:

    def test_missing_2fa_flagged_critical(self):
        """Org without 2FA enforcement must produce CRITICAL finding."""
        Monitor, Finding = get_monitor()
        m = Monitor.__new__(Monitor)
        m.findings = []
        m.org = make_mock_org(two_fa=False)

        m.check_org_settings()

        critical = [f for f in m.findings if f.severity == 'CRITICAL'
                    and '2FA' in f.check or '2fa' in f.check.lower()]
        assert len(critical) >= 1, f'Expected CRITICAL 2FA finding: {m.findings}'

    def test_2fa_enabled_no_finding(self):
        """Org with 2FA enabled must not produce a 2FA finding."""
        Monitor, Finding = get_monitor()
        m = Monitor.__new__(Monitor)
        m.findings = []
        m.org = make_mock_org(two_fa=True)

        m.check_org_settings()

        two_fa_findings = [f for f in m.findings
                           if '2fa' in f.check.lower() or '2FA' in f.check]
        assert len(two_fa_findings) == 0

    def test_outside_collaborators_flagged(self):
        """Outside collaborators must produce MEDIUM finding."""
        Monitor, Finding = get_monitor()
        m = Monitor.__new__(Monitor)
        m.findings = []
        outside = [MagicMock(login='contractor1'), MagicMock(login='contractor2')]
        m.org = make_mock_org(outside_collabs=outside)

        m.check_org_settings()

        collab_findings = [f for f in m.findings
                           if 'collaborator' in f.check.lower()
                           or 'outside' in f.description.lower()]
        assert len(collab_findings) >= 1


# ── Repository-Level Tests ────────────────────────────────────────────────────

class TestRepoChecks:

    def test_unprotected_branch_flagged_high(self):
        """Repo with unprotected main branch must produce HIGH finding."""
        from github import GithubException
        Monitor, Finding = get_monitor()
        m = Monitor.__new__(Monitor)
        m.findings = []
        m.org = MagicMock()

        repo = MagicMock()
        repo.name = 'my-app'
        repo.private = True
        branch = MagicMock()
        branch.get_protection.side_effect = GithubException(404, 'Not protected', {})
        repo.get_branch.return_value = branch
        repo.get_secret_scanning_alerts.return_value = []
        repo.get_workflow_run_default_permissions.return_value = {'default_workflow_permissions': 'read'}

        m._check_branch_protection(repo)

        protection_findings = [f for f in m.findings
                               if 'protection' in f.check.lower()
                               or 'branch' in f.check.lower()]
        assert len(protection_findings) >= 1
        assert all(f.severity in ('HIGH', 'CRITICAL') for f in protection_findings)

    def test_active_secret_alerts_flagged_critical(self):
        """Active secret scanning alerts must produce CRITICAL finding."""
        Monitor, Finding = get_monitor()
        m = Monitor.__new__(Monitor)
        m.findings = []

        secret_alert = MagicMock()
        secret_alert.state = 'open'
        secret_alert.secret_type = 'aws_access_key'

        repo = make_mock_repo(secret_alerts=[secret_alert, secret_alert])
        m._check_security_features(repo)

        secret_findings = [f for f in m.findings
                           if f.severity == 'CRITICAL'
                           and 'secret' in f.check.lower()]
        assert len(secret_findings) >= 1

    def test_write_default_token_perms_flagged_high(self):
        """Actions GITHUB_TOKEN with write permissions must be HIGH."""
        Monitor, Finding = get_monitor()
        m = Monitor.__new__(Monitor)
        m.findings = []

        repo = make_mock_repo(write_token_perms=True)
        m._check_actions_permissions(repo)

        token_findings = [f for f in m.findings
                          if 'token' in f.check.lower()
                          or 'github_token' in f.check.upper()]
        assert len(token_findings) >= 1
        assert any(f.severity in ('HIGH', 'CRITICAL') for f in token_findings)

    def test_protected_repo_no_branch_finding(self):
        """Repo with fully protected main branch must not produce branch findings."""
        Monitor, Finding = get_monitor()
        m = Monitor.__new__(Monitor)
        m.findings = []

        repo = make_mock_repo(protected=True)
        m._check_branch_protection(repo)

        branch_findings = [f for f in m.findings
                           if 'protection' in f.check.lower()
                           and 'missing' in f.description.lower()]
        assert len(branch_findings) == 0


# ── Report Tests ──────────────────────────────────────────────────────────────

class TestReportOutput:

    def test_report_has_required_fields(self):
        """Report must have generated_at, org, summary, and findings."""
        Monitor, Finding = get_monitor()
        m = Monitor.__new__(Monitor)
        m.findings = []
        m.org = MagicMock()
        m.org.login = 'test-org'

        report = m.generate_report()
        assert 'generated_at' in report
        assert 'org' in report
        assert 'summary' in report
        assert 'findings' in report

    def test_severity_counts_accurate(self):
        """Summary severity counts must match findings list."""
        import sys, os
        sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))
        from monitor import SecurityFinding, GitHubSecurityMonitor

        m = GitHubSecurityMonitor.__new__(GitHubSecurityMonitor)
        m.findings = [
            SecurityFinding('CRITICAL', 'Auth', 'repo1', 'Check1', 'desc', 'fix'),
            SecurityFinding('HIGH', 'Auth', 'repo2', 'Check2', 'desc', 'fix'),
            SecurityFinding('HIGH', 'Code', 'repo3', 'Check3', 'desc', 'fix'),
        ]
        m.org = MagicMock()
        m.org.login = 'test-org'

        report = m.generate_report()
        assert report['summary']['by_severity'].get('CRITICAL') == 1
        assert report['summary']['by_severity'].get('HIGH') == 2
