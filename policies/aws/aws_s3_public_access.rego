package grc.aws

import data.grc.aws.helpers

findings contains finding if {
    resource := input[_]

    resource_type := resource.type

    resource_type == "aws_s3_bucket"

    # Check if the bucket is public
    public := helpers.is_public_bucket(resource)

    public

    finding := {
        "policy_id": "AWS001",
        "title": "S3 Bucket Public Access",
        "severity": "high",
        "resource": resource.name,
        "message": sprintf("S3 Bucket %s allows public access", [resource.name]),
        "frameworks": {
            "cis_aws": ["1.1"],
            "nist_800_53": ["AC-3"],
            "fedramp": ["AC-3"]
        }
    }
}