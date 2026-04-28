"""
Unit tests for Kubernetes Cluster Auditor.
Uses unittest.mock to avoid requiring a real cluster.

Run:
    pip install pytest kubernetes
    pytest tests/ -v
"""
import pytest
from unittest.mock import MagicMock, patch, PropertyMock


def get_auditor():
    import sys, os
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
    from src.cluster_auditor import ClusterAuditor, K8sFinding
    return ClusterAuditor, K8sFinding


def make_pod(name: str, namespace: str = 'default',
             privileged: bool = False,
             host_pid: bool = False,
             host_network: bool = False,
             run_as_root: bool = False,
             auto_mount_token: bool = True) -> MagicMock:
    pod = MagicMock()
    pod.metadata.name = name
    pod.metadata.namespace = namespace

    container = MagicMock()
    container.name = f'{name}-container'
    sc = MagicMock()
    sc.privileged = privileged
    sc.run_as_non_root = not run_as_root
    sc.run_as_user = 0 if run_as_root else 1000
    container.security_context = sc
    pod.spec.containers = [container]

    pod.spec.host_pid = host_pid
    pod.spec.host_network = host_network
    pod.spec.host_ipc = False
    pod.spec.automount_service_account_token = auto_mount_token
    pod.spec.security_context = MagicMock()
    pod.spec.security_context.run_as_non_root = not run_as_root
    pod.spec.security_context.run_as_user = 0 if run_as_root else 1000
    return pod


def make_namespace(name: str) -> MagicMock:
    ns = MagicMock()
    ns.metadata.name = name
    return ns


class TestClusterAdminBindings:

    def _make_auditor_with_bindings(self, bindings: list) -> object:
        Auditor, _ = get_auditor()
        with patch('src.cluster_auditor.k8s_config'):
            with patch('src.cluster_auditor.client'):
                a = Auditor.__new__(Auditor)
                a.findings = []
                a.rbac = MagicMock()
                a.rbac.list_cluster_role_binding.return_value.items = bindings
                return a

    def test_cluster_admin_binding_flagged_critical(self):
        binding = MagicMock()
        binding.metadata.name = 'bad-admin-binding'
        binding.role_ref.name = 'cluster-admin'
        subject = MagicMock()
        subject.kind = 'ServiceAccount'
        subject.name = 'my-app'
        subject.namespace = 'default'
        binding.subjects = [subject]

        a = self._make_auditor_with_bindings([binding])
        a.check_cluster_admin_bindings()
        assert len(a.findings) == 1
        assert a.findings[0].severity == 'CRITICAL'
        assert 'cluster-admin' in a.findings[0].description

    def test_system_cluster_admin_not_flagged(self):
        binding = MagicMock()
        binding.metadata.name = 'system:masters'
        binding.role_ref.name = 'cluster-admin'
        subject = MagicMock()
        subject.name = 'system:masters'
        subject.namespace = 'kube-system'
        binding.subjects = [subject]

        a = self._make_auditor_with_bindings([binding])
        a.check_cluster_admin_bindings()
        assert len(a.findings) == 0

    def test_non_admin_role_not_flagged(self):
        binding = MagicMock()
        binding.metadata.name = 'view-binding'
        binding.role_ref.name = 'view'
        subject = MagicMock()
        subject.name = 'my-app'
        subject.namespace = 'default'
        binding.subjects = [subject]

        a = self._make_auditor_with_bindings([binding])
        a.check_cluster_admin_bindings()
        assert len(a.findings) == 0


class TestPrivilegedContainers:

    def _make_auditor_with_pods(self, pods: list) -> object:
        Auditor, _ = get_auditor()
        with patch('src.cluster_auditor.k8s_config'):
            with patch('src.cluster_auditor.client'):
                a = Auditor.__new__(Auditor)
                a.findings = []
                a.v1 = MagicMock()
                ns = make_namespace('default')
                a.v1.list_namespace.return_value.items = [ns]
                a.v1.list_namespaced_pod.return_value.items = pods
                return a

    def test_privileged_container_flagged_critical(self):
        pod = make_pod('evil-pod', privileged=True)
        a = self._make_auditor_with_pods([pod])
        a.check_privileged_containers()
        assert len(a.findings) == 1
        assert a.findings[0].severity == 'CRITICAL'
        assert a.findings[0].mitre_technique == 'T1611'

    def test_non_privileged_container_not_flagged(self):
        pod = make_pod('safe-pod', privileged=False)
        a = self._make_auditor_with_pods([pod])
        a.check_privileged_containers()
        assert len(a.findings) == 0

    def test_host_pid_flagged_high(self):
        pod = make_pod('hostpid-pod', host_pid=True)
        a = self._make_auditor_with_pods([pod])
        a.check_host_namespaces()
        assert len(a.findings) == 1
        assert a.findings[0].severity == 'HIGH'
        assert 'hostPID' in a.findings[0].description


class TestReportGeneration:

    def test_report_severity_ordering(self):
        Auditor, K8sFinding = get_auditor()
        with patch('src.cluster_auditor.k8s_config'):
            with patch('src.cluster_auditor.client'):
                a = Auditor.__new__(Auditor)
                a.findings = [
                    K8sFinding('LOW', 'RBAC', 'ns', 'Pod', 'p', 'd', 'r'),
                    K8sFinding('CRITICAL', 'RBAC', 'ns', 'Pod', 'p', 'd', 'r'),
                    K8sFinding('HIGH', 'RBAC', 'ns', 'Pod', 'p', 'd', 'r'),
                ]
                report = a.generate_report()
        severities = [f['severity'] for f in report['findings']]
        assert severities[0] == 'CRITICAL'
        assert severities[-1] == 'LOW'

    def test_report_counts_accurate(self):
        Auditor, K8sFinding = get_auditor()
        with patch('src.cluster_auditor.k8s_config'):
            with patch('src.cluster_auditor.client'):
                a = Auditor.__new__(Auditor)
                a.findings = [
                    K8sFinding('CRITICAL', 'RBAC', 'ns', 'Pod', 'p', 'd', 'r'),
                    K8sFinding('HIGH', 'RBAC', 'ns', 'Pod', 'p', 'd', 'r'),
                    K8sFinding('HIGH', 'RBAC', 'ns', 'Pod', 'p', 'd', 'r'),
                ]
                report = a.generate_report()
        assert report['summary']['by_severity']['CRITICAL'] == 1
        assert report['summary']['by_severity']['HIGH'] == 2
        assert report['summary']['total'] == 3
