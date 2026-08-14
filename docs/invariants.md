# Invariants

Invariants are org-wide, machine-checked rules evaluated against threat models
— things like "no public endpoints should be unauthenticated" or "all
internet-facing features must document audit logging". They live in their own
HCL file, separate from the threat models themselves, so one rule set can
govern an entire fleet of models.

This document is the language reference: the invariants file format, the
targets, and the expression environment. It is the canonical description for
every consumer of `github.com/threatcl/spec/invariants`:

- **The threatcl CLI** — `threatcl validate -invariants=invariants.hcl ./models/`
  evaluates every invariant against every validated model, failing the run on
  `error`-severity violations. See [threatcl's `docs/invariants.md`][cli-docs]
  for the flag, output format, and exit codes.
- **Threatcl Cloud** — evaluates the same files server-side as a policy engine.
- **Anything else** — the [Go API](#go-api) is a stable, exported part of the
  spec module.

All of them share one parser and one evaluator, so a rule means the same thing
wherever it runs.

[cli-docs]: https://github.com/threatcl/threatcl/blob/main/docs/invariants.md

## The invariants file

An invariants file contains one or more `invariant` blocks:

```hcl
invariant "no_unauthenticated_public_endpoints" {
  description = "No public endpoints should be unauthenticated"
  severity    = "error"
  target      = "process"
  when        = item.trust_zone == "Public"
  condition   = anytrue([for c in tm.controls : c.implemented && can(regex("(?i)auth", c.name))])
}

invariant "internet_facing_models_document_audit_logging" {
  description = "All internet-facing features must emit audit logs"
  severity    = "warning"
  target      = "threatmodel"
  when        = item.attributes.internet_facing
  condition   = anytrue([for c in tm.controls : can(regex("(?i)audit", c.name))])

  error_message = "threatmodel '${item.name}' is internet-facing but documents no audit logging control"

  exemption {
    model         = threatmodel["Legacy Public API"]
    justification = "Grandfathered until Q3 migration; tracked in SEC-123"
  }
}

invariant "threats_have_implemented_controls" {
  description = "Every threat must have at least one implemented control"
  target      = "threat"
  condition   = anytrue([for c in item.controls : c.implemented])
}
```

Invariant names are the block labels and must be unique within a file.

### Attributes

| Attribute       | Required | Meaning                                                                                                     |
| --------------- | -------- | ----------------------------------------------------------------------------------------------------------- |
| `target`        | yes      | Which collection the rule applies to (see [Targets](#targets)). The condition runs once per item.            |
| `condition`     | yes      | HCL expression that must evaluate to `true` for each targeted item. `false` records a violation.             |
| `when`          | no       | HCL expression filtering which items the rule applies to. Items where `when` is `false` are skipped.         |
| `severity`      | no       | `"error"` (default) or `"warning"`. Consumers treat only error violations as failing.                        |
| `description`   | no       | Human explanation; used as the violation message when `error_message` isn't set.                             |
| `error_message` | no       | HCL string expression for the violation message. May interpolate `item`, `tm`, and (for DFD targets) `dfd`.  |

### Exemptions

An `exemption` block waives the invariant for one threat model, with a
required justification so the waiver is auditable:

```hcl
exemption {
  model         = threatmodel["Legacy Public API"]
  justification = "Why this model is allowed to violate the rule"
}
```

`model` is a real reference, not a string: `threatmodel` is a registry of the
models in the current evaluation run, addressable two ways.

- **By display name**, with index syntax: `threatmodel["Legacy Public API"]`.
- **By identifier, with dot notation**: `threatmodel.legacy_public_api`. A
  model's identifier is its declared `id` attribute when present, else one
  derived from its name (`"Tower of London"` → `tower_of_london`). Dotted ids
  nest — a model with `id = "buildings.tower"` is `threatmodel.buildings.tower`
  — and a model whose id *is* the namespace (`id = "buildings"`) is the parent:
  it resolves at that address itself, with its children alongside its fields.

Referencing a model that isn't in the run is a hard error that lists the
models that are — so a typo'd or renamed model can't leave a silently-dead
waiver behind. Identifier collisions across the run (two models whose
declared-or-derived identifiers coincide), a child id segment that shadows a
parent model's field, or a model name that collides with another model's id
are also hard errors: every address must mean exactly one thing. Because the
reference resolves to the actual model object, field access works too
(`threatmodel["Legacy Public API"].author`), though an exemption's `model`
must be the model itself, not a field of it.

If one invariants file is shared across fleets that are evaluated separately,
wrap the reference so it's inactive where the model isn't present:

```hcl
model = try(threatmodel["Other Fleet's Model"], null)
```

A consumer that evaluates a subset of the fleet by design — Threatcl Cloud
evaluates one model at a time — can instead ask for the whole file to be read
leniently; see [`WithLenientExemptions`](#go-api). Either way the exemption is
recorded as inactive rather than silently dropped.

Exemptions live in the invariants file — not in the threat model — so models
can't waive rules for themselves. Exempted models are skipped (not evaluated)
and reported with their justification.

## Targets

The `target` attribute picks the collection each item comes from. The
condition is evaluated once per item, so violations name the exact offending
item.

| Target                   | Item                                                                                    |
| ------------------------ | --------------------------------------------------------------------------------------- |
| `threatmodel`            | The threat model itself (one item per model)                                             |
| `threat`                 | Each `threat` block                                                                      |
| `control`                | Each control across all threats (inline `control` blocks plus imported controls)         |
| `information_asset`      | Each `information_asset` block                                                           |
| `usecase`                | Each `usecase` block                                                                     |
| `exclusion`              | Each `exclusion` block                                                                   |
| `third_party_dependency` | Each `third_party_dependency` block                                                      |
| `data_flow_diagram`      | Each `data_flow_diagram_v2` block (legacy `data_flow_diagram` blocks are included too)   |
| `process`                | Each DFD process, including those nested in `trust_zone` blocks                          |
| `external_element`       | Each DFD external element, including nested                                              |
| `data_store`             | Each DFD data store, including nested                                                    |
| `flow`                   | Each DFD flow                                                                            |
| `trust_zone`             | Each DFD trust zone                                                                      |

Items with no name of their own (`usecase`, `exclusion`) are reported by their
1-based position — `usecase #2`.

## Expressions

`when`, `condition`, and `error_message` are native HCL expressions. Three
variables are in scope:

- `item` — the current target item.
- `tm` — the threat model that owns the item (for `target = "threatmodel"`,
  `item` and `tm` are the same object).
- `dfd` — the owning diagram, only for the DFD element targets (`process`,
  `external_element`, `data_store`, `flow`, `trust_zone`).

Referencing any other variable is a parse error, so a typo fails when the file
is read rather than when a particular model happens to be evaluated.

### The `tm` object

| Field                      | Type           | Notes                                                              |
| -------------------------- | -------------- | ------------------------------------------------------------------ |
| `name`, `description`, `author`, `link`, `diagram_link` | string | |
| `id`, `extends`            | string         | The declared `id`/`extends` attributes (empty when not declared). Models a rule sees have `extends` inheritance already applied. |
| `repository`               | list(string)   |                                                                    |
| `created_at`, `updated_at` | number         | Unix timestamps                                                    |
| `attributes`               | object         | `new_initiative` (bool), `internet_facing` (bool), `initiative_size` (string); all-defaults when the block is absent |
| `additional_attributes`    | map(string)    | `additional_attribute` blocks as a name → value map                |
| `information_assets`       | list(object)   | `name`, `description`, `information_classification`, `source`, `ref` |
| `threats`                  | list(object)   | See below                                                          |
| `usecases`, `exclusions`   | list(object)   | Each has `description`                                             |
| `third_party_dependencies` | list(object)   | `name`, `description`, `saas`, `paying_customer`, `open_source`, `uptime_dependency`, `uptime_notes`, `infrastructure` |
| `data_flow_diagrams`       | list(object)   | See below                                                          |
| `controls`                 | list(object)   | Convenience: every control across every threat, flattened          |

Each threat has `name`, `description`, `impacts`, `stride`,
`information_asset_refs`, `control` (the legacy string attribute), `ref`,
`controls`, `proposed_controls`, and `risk` (an object with `likelihood`,
`impact`, `severity`, `rationale` — or `null` when the threat has no risk
block). Each control has `name`, `implemented`, `description`,
`implementation_notes`, `ref`, `risk_reduction`, and `attributes` (a
name → value map of its `attribute` blocks).

Each data flow diagram has `name`, `processes`, `external_elements`,
`data_stores`, `flows`, and `trust_zones`. The element lists include elements
nested inside `trust_zone` blocks, and every element's `trust_zone` field is
resolved (nested elements report the enclosing zone). Flows have `name`,
`from`, `to`, `protocol`.

Every string field is present (empty rather than null), so comparisons like
`item.protocol != ""` are safe without null checks.

### Functions

The usual expression toolkit is available: `alltrue`, `anytrue`, `can`, `try`,
`coalesce`, `compact`, `concat`, `contains`, `distinct`, `element`, `flatten`,
`format`, `join`, `keys`, `length`, `lookup`, `lower`, `max`, `merge`, `min`,
`regex`, `regexall`, `replace`, `reverse`, `sort`, `split`, `substr`, `trim`,
`trimprefix`, `trimspace`, `trimsuffix`, `upper`, `values`, `zipmap`. These
behave like their Terraform counterparts.

Quantification uses `for` expressions:

```hcl
# every: all controls implemented
condition = alltrue([for c in item.controls : c.implemented])

# exists: at least one confidential asset
condition = anytrue([for a in tm.information_assets : a.information_classification == "Confidential"])

# none: no flow uses plain http
condition = length([for f in item.flows : f if lower(f.protocol) == "http"]) == 0
```

## Go API

```go
import "github.com/threatcl/spec/invariants"
```

Parsing and evaluation are the two seams. An `Invariant` is only constructible
by parsing — its expression fields are unexported — so a rule value that exists
has already been validated.

```go
invs, err := invariants.ParseFile("invariants.hcl")
// or, for bytes you already hold (filename is used in diagnostics only):
invs, err := invariants.ParseHCLRaw(src, "invariants.hcl")
```

`Evaluate` checks every invariant against every model. A `*Model` pairs a
parsed `*spec.Threatmodel` with the file it came from, for reporting:

```go
models := []*invariants.Model{{TM: tm, File: "models/payments.hcl"}}

report, err := invariants.Evaluate(invs, models)
```

A returned error means an invariant itself is broken — its expression failed to
evaluate, produced the wrong type, or its exemption named a model that isn't
there — as opposed to a model merely violating a rule. Violations are in the
report, not the error.

### Report

| Field                | Meaning                                                                    |
| -------------------- | -------------------------------------------------------------------------- |
| `Violations`         | `[]*Violation` — invariant, model, `ItemKind`, `ItemName`, `Message`        |
| `Exemptions`         | `[]*ExemptionUse` — invariant, model, justification: waivers that applied   |
| `InactiveExemptions` | `[]*InactiveExemption` — waivers that named no model in this run            |
| `Invariants`         | Number of invariants evaluated                                             |
| `Models`             | Number of models evaluated                                                 |

`ErrorCount()` and `WarningCount()` split violations by their invariant's
severity. Ordering is deterministic: models in input order, then invariants in
file order, then items in model order.

An `InactiveExemption` carries the invariant, the `Reference` (the source text
of the exemption's `model` expression, exactly as written), the
`Justification`, and a `Reason` — `"resolved to null"` for a
`try(..., null)` reference, or the resolution error text under lenient mode.

### Evaluating a subset of the fleet

By default a reference to a model that isn't in the run is a hard error, which
is what you want when the run *is* the fleet. A caller that deliberately
evaluates a shared invariants file against a subset — one model at a time, say
— can relax that:

```go
report, err := invariants.Evaluate(invs, models, invariants.WithLenientExemptions())
```

Unresolvable exemption references then become inactive and are recorded in
`Report.InactiveExemptions` instead of failing the run. Everything else stays
strict: an exemption resolving to something that isn't a model, and errors
building the model registry (identifier collisions, shadowed segments), are
still hard errors in either mode — those are a malformed file or an
unaddressable set of models, not a scoping question.
