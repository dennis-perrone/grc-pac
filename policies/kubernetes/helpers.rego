package grc.kubernetes.helpers

containers(resource) = containers if {
    resource.kind == "Pod"
    containers := resource.spec.containers
}

containers(resource) = containers if {
    resource.kind != "Pod"
    containers := resource.spec.template.spec.containers
}