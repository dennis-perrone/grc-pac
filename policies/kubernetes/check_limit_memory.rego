package grc.kubernetes

import data.grc.kubernetes.helpers

findings contains finding if {
    resource := input[_]

    container := helpers.containers(resource)[_]

    not container.resources.limits.memory

    finding := {
        "policy_id": "K8S003",
        "title": "Container missing memory limits",
        "severity": "medium",
        "resource": resource.metadata.name,
        "message": sprintf("Container %v missing memory limits", [container.name]),
        "frameworks": {
            "cis_kubernetes": ["5.4.3"],
            "nist_800_53": ["CM-6"],
            "fedramp": ["CM-6"]
        }
    }
}