package main

deny[msg] {
  input[i].kind == "HelmRelease"
  name := input[i].spec.releaseName

  input[j].kind == "HelmRelease"
  other_name := input[j].spec.releaseName

  i != j
  name == other_name

  msg := sprintf("release \"%s\" from %s is duplicate with %s file", [name, i, j])
}
