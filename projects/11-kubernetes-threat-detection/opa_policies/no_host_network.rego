package kubernetes.security.no_host_network

# METADATA
# title: Deny hostNetwork/hostPID/hostIPC
# severity: CRITICAL — enables container escape

violation[{"msg": msg}] {
    input.review.object.spec.hostNetwork == true
    msg := "Pod uses hostNetwork — grants access to host network namespace. Forbidden."
}

violation[{"msg": msg}] {
    input.review.object.spec.hostPID == true
    msg := "Pod uses hostPID — grants visibility into all host processes. Forbidden."
}

violation[{"msg": msg}] {
    input.review.object.spec.hostIPC == true
    msg := "Pod uses hostIPC — grants access to host IPC namespace. Forbidden."
}
