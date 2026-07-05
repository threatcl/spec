spec_version = "0.5.0"

threatmodel "slug refs" {
  author = "@xntrik"

  information_asset "Customer Data" {
    description                = "PII we hold about customers"
    information_classification = "Confidential"
  }

  threat "stolen data" {
    description = "Someone steals the customer data"
    information_asset_refs = [
      information_asset.customer_data,
    ]
  }

  data_flow_diagram_v2 "dfd" {
    process "Web App" {}

    process "Backend Worker" {
      trust_zone = trust_zone.internal_zone
    }

    external_element "End User" {}

    data_store "User Database" {
      information_asset = "customer-data"
      trust_zone        = "internal-zone"
    }

    trust_zone "Internal Zone" {
      process "Batch Job" {
        trust_zone = "internal-zone"
      }
    }

    flow "https" {
      from = external_element.end_user
      to   = process.web_app
    }

    flow "sql" {
      from = process.web_app
      to   = data_store.user_database
    }

    flow "queue" {
      from = "web-app"
      to   = "Backend Worker"
    }
  }
}
