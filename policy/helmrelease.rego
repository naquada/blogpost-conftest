package main

deny[msg] {
  input[i].kind == "HelmRelease"
  input[j].kind == "HelmRelease"
  i != j
  input[i].spec.releaseName == input[j].spec.releaseName
  msg := sprintf("release \"%s\" from %s is duplicate with %s file", [input[i].spec.releaseName, i, j])
}
