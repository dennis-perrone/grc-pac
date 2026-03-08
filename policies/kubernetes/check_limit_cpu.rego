package grc.kubernetes

import data.grc.kubernetes.helpers

findings contains finding if {
    resource := input[_]

    container := helpers.containers(resource)[_]

    not container.resources.limits.cpu

    finding := {
        "policy_id": "K8S002",
        "title": "Container missing CPU limits",
        "severity": "medium",
        "category": "resource_management",
        "resource": resource.metadata.name,
        "container": container.name,
        "message": sprintf("Container %v missing CPU limits", [container.name]),
        "frameworks": {
            "cis_kubernetes": ["5.4.2"],
            "nist_800_53": ["CM-6"],
            "fedramp": ["CM-6"]
        }
    }
}