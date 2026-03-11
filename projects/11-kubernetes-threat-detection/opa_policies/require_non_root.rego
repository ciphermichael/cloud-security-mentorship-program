package kubernetes.security.require_non_root

import future.keywords.in

# METADATA
# title: Require Non-Root User
# severity: HIGH

violation[{"msg": msg}] {
    container := input.review.object.spec.containers[_]
    not container.securityContext.runAsNonRoot == true
    not container.securityContext.runAsUser > 0
    msg := sprintf(
        "Container '%v' must set runAsNonRoot: true or runAsUser > 0",
        [container.name]
    )
}

violation[{"msg": msg}] {
    container := input.review.object.spec.containers[_]
    container.securityContext.runAsUser == 0
    msg := sprintf(
        "Container '%v' explicitly runs as root (UID 0) — forbidden",
        [container.name]
    )
}
