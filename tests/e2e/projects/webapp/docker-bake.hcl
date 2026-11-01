# `dist` exports the app's files; `ci` uses a build cache and credentials from the build host.
variable "TAG" {
  default = "dev"
}

variable "HOME" {
  default = ""
}

variable "BUILDKIT_CACHE" {
  default = "${HOME}/.cache/buildkit"
}

variable "NPMRC" {
  default = "${HOME}/.npmrc"
}

group "default" {
  targets = ["app"]
}

target "app" {
  context = "."
  tags    = ["dockscreen-e2e/webapp:${TAG}"]
}

target "dist" {
  inherits = ["app"]
  output   = ["type=local,dest=dist"]
}

target "ci" {
  inherits   = ["app"]
  cache-from = ["type=local,src=${BUILDKIT_CACHE}"]
  cache-to   = ["type=local,dest=${BUILDKIT_CACHE}"]
  secret     = ["id=npmrc,src=${NPMRC}"]
  ssh        = ["default"]
}
