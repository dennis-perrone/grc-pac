package grc.aws.helpers

# Iterate over resources
resources := input

# Extract resource name safely
resource_name(resource) := name if {
    name := resource.metadata.name
} else := "unknown"

# Extract resource kind
resource_kind(resource) := kind if {
    kind := resource.kind
} else := "unknown"

# Build a standardized finding
build_finding(policy_id, title, severity, resource, message, frameworks) := {
    "policy_id": policy_id,
    "title": title,
    "severity": severity,
    "resource": resource_name(resource),
    "resource_type": resource_kind(resource),
    "message": message,
    "frameworks": frameworks
}

# Check if IAM has inline roles
has_inline_policies(role) if {
    count(role.inline_policies) > 0
}

# Check if IAM action contains wildcard
is_wildcard_action(action) if {
    action == "*"
}

is_wildcard_action(action) if {
    contains(action, "*")
}

# Check if resource is publicly accessible
is_public_acl(acl) if {
    acl == "public-read"
}

is_public_acl(acl) if {
    acl == "public-read-write"
}

is_public_bucket(bucket) if {
    bucket.acl == "public-read"
}

is_public_bucket(bucket) if {
    bucket.acl == "public-read-write"
}

# Check encryption state
is_encrypted(resource) if {
    resource.spec.storageEncrypted == true
}

# Generic "not encrypted" helper
not_encrypted(resource) if {
    not is_encrypted(resource)
}

# Severity helpers
severity_high := "high"
severity_medium := "medium"
severity_low := "low"