package main

deny[msg] {
  input[i].kind == "VirtualService"
  host := input[i].spec.hosts[_]

  input[j].kind == "VirtualService"
  other_host := input[j].spec.hosts[_]

  i != j
  host == other_host

  msg := sprintf("host \"%s\" from %s is duplicate with %s file", [host, i, j])
}
