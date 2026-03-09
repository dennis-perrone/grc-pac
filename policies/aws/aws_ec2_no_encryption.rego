package grc.aws

import data.grc.aws.helpers

findings contains finding if {
    resource := input[_]

    resource_type := resource.type

    resource_type == "aws_ebs_volume"

    not resource.encrypted

    finding := {
        "policy_id": "AWS003",
        "title": "EBS Volume Not Encrypted",
        "severity": "high",
        "resource": resource.name,
        "message": sprintf("EBS Volume %s is not encrypted", [resource.name]),
        "frameworks": {
            "cis_aws": ["2.1"],
            "nist_800_53": ["SC-28"],
            "fedramp": ["SC-28"]
        }
    }
}