package grc.aws

import data.grc.aws.helpers

findings contains finding if {
    resource := input[_]

    resource_type := resource.type

    resource_type == "aws_iam_user"

    has_inline := helpers.has_inline_policies(resource)

    has_inline

    finding := {
        "policy_id": "AWS002",
        "title": "IAM User with Inline Policies",
        "severity": "medium",
        "resource": resource.name,
        "message": sprintf("IAM User %s has inline policies, which are harder to audit", [resource.name]),
        "frameworks": {
            "cis_aws": ["1.7"],
            "nist_800_53": ["AC-2"],
            "fedramp": ["AC-2"]
        }
    }
}