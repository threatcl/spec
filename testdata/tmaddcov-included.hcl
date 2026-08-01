spec_version = "0.7.0"

threatmodel "Coverage Castle Base" {
  description = "Base model for include coverage"
  author = "@coverage"

  usecase {
    description = "shared use case"
  }

  usecase {
    description = "included-only use case"
  }

  exclusion {
    description = "shared exclusion"
  }

  exclusion {
    description = "included-only exclusion"
  }

  third_party_dependency "shared tpd" {
    description = "included copy of the shared third party dependency"
    uptime_dependency = "degraded"
  }

  third_party_dependency "included tpd" {
    description = "included-only third party dependency"
    uptime_dependency = "degraded"
  }

  data_flow_diagram_v2 "shared dfd" {
    process "base proc" {}
  }

  data_flow_diagram_v2 "included dfd" {
    process "included proc" {}
  }

  mermaid "shared mermaid" {
    content = "graph TD; A-->B;"
  }

  mermaid "included mermaid" {
    content = "graph TD; C-->D;"
  }

}
