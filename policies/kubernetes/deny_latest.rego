package grc.kubernetes

import data.grc.kubernetes.helpers

findings contains finding if {
    resource := input[_]

    container := helpers.containers(resource)[_]

    endswith(container.image, ":latest")

    finding := {
        "policy_id": "K8S001",
        "title": "Container uses latest tag",
        "severity": "high",
        "resource": resource.metadata.name,
        "container": container.name,
        "message": sprintf("Container %s uses 'latest' tag", [container.name]),
        "frameworks": {
            "cis_kubernetes": ["5.4.1"],
            "nist_800_53": ["CM-6"],
            "fedramp": ["CM-6"]
        }
    }
}