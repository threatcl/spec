spec_version = "0.8.0"

threatmodel "Coverage Castle" {

  author = "@coverage"

  including = "tmaddcov-included.hcl"

  usecase {
    description = "shared use case"
  }

  exclusion {
    description = "shared exclusion"
  }

  third_party_dependency "shared tpd" {
    description = "parent copy of the shared third party dependency"
    uptime_dependency = "degraded"
  }

  data_flow_diagram_v2 "shared dfd" {
    process "parent proc" {}
  }

  mermaid "shared mermaid" {
    content = "graph TD; P-->Q;"
  }

}
