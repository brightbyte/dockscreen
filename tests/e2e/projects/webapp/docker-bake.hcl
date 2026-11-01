# `dist` exports the app's files; `ci` uses a build cache and credentials from the build host.
variable "TAG" {
  default = "dev"
}

variable "HOME" {
  default = ""
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
  cache-from = ["type=local,src=${HOME}/.cache/buildkit"]
  cache-to   = ["type=local,dest=${HOME}/.cache/buildkit"]
  secret     = ["id=npmrc,src=${HOME}/.npmrc"]
  ssh        = ["default"]
}
