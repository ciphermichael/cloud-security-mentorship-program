# =============================================================================
# OPA Rego Policy — No Privileged Containers
# Project 11 — Kubernetes Threat Detection
# Enforced via OPA Gatekeeper ConstraintTemplate
# =============================================================================
package kubernetes.security.no_privileged

import future.keywords.in

# METADATA
# title: Deny Privileged Containers
# description: >
#   Containers must not run in privileged mode. Privileged containers have
#   access to all Linux capabilities and host namespaces, making container
#   escape trivial.
# severity: CRITICAL
# mitre_technique: T1611 — Escape to Host

violation[{"msg": msg}] {
    container := input.review.object.spec.containers[_]
    container.securityContext.privileged == true
    msg := sprintf(
        "Container '%v' in pod '%v' is privileged — this is forbidden. Remove securityContext.privileged or set to false.",
        [container.name, input.review.object.metadata.name]
    )
}

violation[{"msg": msg}] {
    container := input.review.object.spec.initContainers[_]
    container.securityContext.privileged == true
    msg := sprintf(
        "Init container '%v' in pod '%v' is privileged.",
        [container.name, input.review.object.metadata.name]
    )
}
