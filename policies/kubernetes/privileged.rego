package grc.kubernetes

import data.grc.kubernetes.helpers

findings contains finding if {
    resource := input[_]

    container := helpers.containers(resource)[_]

    container.securityContext.privileged

    finding := {
        "policy_id": "K8S004",
        "title": "Privileged container",
        "severity": "high",
        "resource": resource.metadata.name,
        "message": sprintf("Container %v is running privileged", [container.name]),
        "frameworks": {
            "cis_kubernetes": ["5.4.4"],
            "nist_800_53": ["CM-6"],
            "fedramp": ["CM-6"]
        }
    }
}