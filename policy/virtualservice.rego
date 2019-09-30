package main

deny[msg] {
  input[i].kind == "VirtualService"
  input[j].kind == "VirtualService"
  i != j
  input[i].spec.hosts[k] == input[j].spec.hosts[_]
  msg := sprintf("host \"%s\" from %s is duplicate with %s file", [input[i].spec.hosts[k], i, j])
}
