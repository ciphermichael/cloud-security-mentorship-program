"""
Kubernetes Security Cluster Auditor.
Connects to a running cluster and checks RBAC, pod security,
network policies, and Falco rule coverage.

Requirements:
    pip install kubernetes

Usage:
    python -m src.cluster_auditor --kubeconfig ~/.kube/config
"""
import json
import logging
import sys
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path

logger = logging.getLogger(__name__)

try:
    from kubernetes import client, config as k8s_config
    from kubernetes.client.rest import ApiException
    K8S_AVAILABLE = True
except ImportError:
    K8S_AVAILABLE = False
    logger.warning('kubernetes package not installed. Install: pip install kubernetes')


@dataclass
class K8sFinding:
    severity: str          # CRITICAL | HIGH | MEDIUM | LOW
    category: str          # RBAC | PodSecurity | NetworkPolicy | Config
    namespace: str
    resource_type: str
    resource_name: str
    description: str
    remediation: str
    mitre_technique: str = ''
    mitre_tactic: str = ''


class ClusterAuditor:

    def __init__(self, kubeconfig: str | None = None, context: str | None = None):
        if not K8S_AVAILABLE:
            raise RuntimeError('Install kubernetes client: pip install kubernetes')
        if kubeconfig:
            k8s_config.load_kube_config(config_file=kubeconfig, context=context)
        else:
            try:
                k8s_config.load_incluster_config()
            except Exception:
                k8s_config.load_kube_config(context=context)

        self.v1 = client.CoreV1Api()
        self.rbac = client.RbacAuthorizationV1Api()
        self.apps = client.AppsV1Api()
        self.networking = client.NetworkingV1Api()
        self.findings: list[K8sFinding] = []

    def _add(self, **kwargs):
        self.findings.append(K8sFinding(**kwargs))

    # ── RBAC Checks ───────────────────────────────────────────────────────────

    def check_cluster_admin_bindings(self):
        """Flag any ClusterRoleBinding to cluster-admin that isn't system:."""
        bindings = self.rbac.list_cluster_role_binding().items
        for binding in bindings:
            if binding.role_ref.name != 'cluster-admin':
                continue
            for subject in binding.subjects or []:
                if subject.name.startswith('system:') or subject.namespace == 'kube-system':
                    continue
                self._add(
                    severity='CRITICAL',
                    category='RBAC',
                    namespace=subject.namespace or 'cluster-wide',
                    resource_type=subject.kind,
                    resource_name=subject.name,
                    description=f'{subject.kind} "{subject.name}" has cluster-admin '
                                f'via binding "{binding.metadata.name}".',
                    remediation='Remove cluster-admin. Grant only necessary RBAC roles.',
                    mitre_technique='T1078',
                    mitre_tactic='Privilege Escalation',
                )

    def check_service_account_tokens_automounted(self):
        """Flag pods that auto-mount service account tokens unnecessarily."""
        for ns in self.v1.list_namespace().items:
            ns_name = ns.metadata.name
            if ns_name in ('kube-system', 'kube-public', 'kube-node-lease'):
                continue
            pods = self.v1.list_namespaced_pod(ns_name).items
            for pod in pods:
                spec = pod.spec
                auto_mount = spec.automount_service_account_token
                if auto_mount is None or auto_mount is True:
                    self._add(
                        severity='MEDIUM',
                        category='RBAC',
                        namespace=ns_name,
                        resource_type='Pod',
                        resource_name=pod.metadata.name,
                        description=f'Pod auto-mounts service account token. '
                                    f'If the pod doesn\'t need Kubernetes API access, '
                                    f'this is an unnecessary credential exposure.',
                        remediation='Set automountServiceAccountToken: false in pod spec '
                                    'or service account.',
                        mitre_technique='T1528',
                        mitre_tactic='Credential Access',
                    )

    # ── Pod Security Checks ───────────────────────────────────────────────────

    def check_privileged_containers(self):
        """Flag pods running privileged containers."""
        for ns in self.v1.list_namespace().items:
            ns_name = ns.metadata.name
            pods = self.v1.list_namespaced_pod(ns_name).items
            for pod in pods:
                for container in (pod.spec.containers or []):
                    sc = container.security_context
                    if sc and sc.privileged:
                        self._add(
                            severity='CRITICAL',
                            category='PodSecurity',
                            namespace=ns_name,
                            resource_type='Container',
                            resource_name=f'{pod.metadata.name}/{container.name}',
                            description=f'Container "{container.name}" runs as privileged '
                                        f'(securityContext.privileged: true). '
                                        f'Has full host kernel access.',
                            remediation='Remove privileged: true. Use specific capabilities instead.',
                            mitre_technique='T1611',
                            mitre_tactic='Privilege Escalation',
                        )

    def check_host_namespaces(self):
        """Flag pods sharing host PID, network, or IPC namespaces."""
        for ns in self.v1.list_namespace().items:
            ns_name = ns.metadata.name
            pods = self.v1.list_namespaced_pod(ns_name).items
            for pod in pods:
                spec = pod.spec
                issues = []
                if spec.host_pid:
                    issues.append('hostPID: true')
                if spec.host_network:
                    issues.append('hostNetwork: true')
                if spec.host_ipc:
                    issues.append('hostIPC: true')
                if issues:
                    self._add(
                        severity='HIGH',
                        category='PodSecurity',
                        namespace=ns_name,
                        resource_type='Pod',
                        resource_name=pod.metadata.name,
                        description=f'Pod shares host namespaces: {", ".join(issues)}.',
                        remediation='Remove hostPID, hostNetwork, hostIPC from pod spec.',
                        mitre_technique='T1611',
                        mitre_tactic='Privilege Escalation',
                    )

    def check_containers_running_as_root(self):
        """Flag containers that run as UID 0 or do not set runAsNonRoot."""
        for ns in self.v1.list_namespace().items:
            ns_name = ns.metadata.name
            pods = self.v1.list_namespaced_pod(ns_name).items
            for pod in pods:
                pod_sc = pod.spec.security_context
                for container in (pod.spec.containers or []):
                    c_sc = container.security_context
                    run_as_non_root = (
                        (c_sc and c_sc.run_as_non_root) or
                        (pod_sc and pod_sc.run_as_non_root)
                    )
                    run_as_user = (
                        (c_sc and c_sc.run_as_user) or
                        (pod_sc and pod_sc.run_as_user)
                    )
                    if not run_as_non_root and (run_as_user is None or run_as_user == 0):
                        self._add(
                            severity='HIGH',
                            category='PodSecurity',
                            namespace=ns_name,
                            resource_type='Container',
                            resource_name=f'{pod.metadata.name}/{container.name}',
                            description=f'Container "{container.name}" may run as root '
                                        f'(no runAsNonRoot: true or runAsUser > 0).',
                            remediation='Set runAsNonRoot: true and runAsUser: 1000+ '
                                        'in container securityContext.',
                            mitre_technique='T1548',
                            mitre_tactic='Privilege Escalation',
                        )

    # ── Network Policy Checks ─────────────────────────────────────────────────

    def check_namespaces_without_network_policy(self):
        """Flag namespaces with pods but no NetworkPolicy (no micro-segmentation)."""
        for ns in self.v1.list_namespace().items:
            ns_name = ns.metadata.name
            if ns_name in ('kube-system', 'kube-public', 'kube-node-lease'):
                continue
            pods = self.v1.list_namespaced_pod(ns_name).items
            if not pods:
                continue
            netpols = self.networking.list_namespaced_network_policy(ns_name).items
            if not netpols:
                self._add(
                    severity='MEDIUM',
                    category='NetworkPolicy',
                    namespace=ns_name,
                    resource_type='Namespace',
                    resource_name=ns_name,
                    description=f'Namespace "{ns_name}" has {len(pods)} pod(s) '
                                f'but no NetworkPolicy. All pod-to-pod traffic is unrestricted.',
                    remediation='Apply a default-deny NetworkPolicy, then add '
                                'explicit allow rules for required traffic.',
                    mitre_technique='T1046',
                    mitre_tactic='Discovery',
                )

    # ── Runner ────────────────────────────────────────────────────────────────

    def run_all_checks(self):
        checks = [
            ('RBAC: cluster-admin bindings', self.check_cluster_admin_bindings),
            ('RBAC: auto-mounted SA tokens', self.check_service_account_tokens_automounted),
            ('PodSecurity: privileged containers', self.check_privileged_containers),
            ('PodSecurity: host namespaces', self.check_host_namespaces),
            ('PodSecurity: root containers', self.check_containers_running_as_root),
            ('NetworkPolicy: missing policies', self.check_namespaces_without_network_policy),
        ]
        for label, fn in checks:
            try:
                print(f'[*] Checking {label}...')
                fn()
            except Exception as e:
                print(f'  [WARN] {label} failed: {e}')

    def generate_report(self) -> dict:
        order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3}
        sorted_findings = sorted(self.findings, key=lambda f: order.get(f.severity, 9))
        counts: dict[str, int] = {}
        for f in sorted_findings:
            counts[f.severity] = counts.get(f.severity, 0) + 1
        return {
            'generated_at': datetime.now(timezone.utc).isoformat(),
            'framework': 'Kubernetes CIS Benchmark + MITRE ATT&CK',
            'summary': {'total': len(sorted_findings), 'by_severity': counts},
            'findings': [asdict(f) for f in sorted_findings],
        }


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description='Kubernetes Security Cluster Auditor')
    parser.add_argument('--kubeconfig', default=None)
    parser.add_argument('--context', default=None)
    parser.add_argument('--output', default='reports')
    args = parser.parse_args()

    auditor = ClusterAuditor(kubeconfig=args.kubeconfig, context=args.context)
    auditor.run_all_checks()
    report = auditor.generate_report()

    out = Path(args.output)
    out.mkdir(exist_ok=True)
    outfile = out / f'k8s-audit-{datetime.now().strftime("%Y-%m-%d")}.json'
    outfile.write_text(json.dumps(report, indent=2))
    print(f'\n[+] K8s audit complete: {report["summary"]["total"]} findings → {outfile}')
