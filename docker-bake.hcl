variable "REGISTRY" { default = "10.10.10.245:5000/devin" }
variable "TAG" { default = "dev" }

group "default" {
    targets = ["auth_backend", "gradegetter", "gradegetter_backend", "nanopass_backend", "notification_backend", "smalltalk_backend"]
}

target "settings" {
    context = "."
    output = ["type=registry,registry.insecure=true"]
}

target "auth_backend" {
    inherits = ["settings"]
    dockerfile = "Dockerfile.auth_backend"
    tags = ["${REGISTRY}/auth_backend:${TAG}"]
}

target "gradegetter" {
    inherits = ["settings"]
    dockerfile = "Dockerfile.gradegetter"
    tags = ["${REGISTRY}/gradegetter:${TAG}"]
}

target "gradegetter_backend" {
    inherits = ["settings"]
    dockerfile = "Dockerfile.gradegetter_backend"
    tags = ["${REGISTRY}/gradegetter_backend:${TAG}"]
}

target "nanopass_backend" {
    inherits = ["settings"]
    dockerfile = "Dockerfile.nanopass_backend"
    tags = ["${REGISTRY}/nanopass_backend:${TAG}"]
}

target "notification_backend" {
    inherits = ["settings"]
    dockerfile = "Dockerfile.notification_backend"
    tags = ["${REGISTRY}/notification_backend:${TAG}"]
}

target "smalltalk_backend" {
    inherits = ["settings"]
    dockerfile = "Dockerfile.smalltalk_backend"
    tags = ["${REGISTRY}/smalltalk_backend:${TAG}"]
}
