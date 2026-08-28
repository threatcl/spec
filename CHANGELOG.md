## 0.8.1

### 28 Aug, 2026

CHANGES:

* Bumped to golang 1.27.0

## 0.8.0

### 15 Aug, 2026

CHANGES:

* New `github.com/threatcl/spec/invariants` subpackage: the parser and
  evaluator for invariants files — org-wide, machine-checked rules over threat
  models — extracted from the threatcl CLI's `internal/invariants` (threatcl
  v0.6.5) with no behavioural change, so every consumer shares one evaluator
  and verdicts agree by construction. `ParseFile`/`ParseHCLRaw` and `Evaluate`
  are the seams; `Invariant` remains constructible only by parsing. The
  language reference now lives at [docs/invariants.md](docs/invariants.md).
* `Evaluate` takes variadic `EvaluateOption`s. `Evaluate(invs, models)` is
  unchanged; `WithLenientExemptions()` makes an exemption whose model
  reference can't be resolved against the models in the run inactive rather
  than a hard error, for callers evaluating a shared invariants file against a
  subset of the fleet (one model at a time). Malformed references and model
  registry errors stay hard errors in both modes.
* `Report` gains `InactiveExemptions []*InactiveExemption` — the waivers that
  named no model in this run, each with the invariant, the source text of its
  `model` expression, its justification, and a reason. This includes
  `try(threatmodel["Other"], null)` references in the default strict mode,
  which were previously skipped silently.
* `Exemption` gains an exported `Reference string`: the source text of its
  `model` expression, captured at parse time.

## 0.7.0

### 1 Aug, 2026

CHANGES:

* BREAKING: `ValidateTm` now rejects duplicate names among a threat model's
  entities, alongside the existing `information_asset`, `trust_zone`, DFD
  element and flow checks:
  * two `threat` blocks with the same name in one `threatmodel`
    (`TM '<tm>': duplicate threat '<name>'`), and
  * two `control` blocks with the same name in one `threat`
    (`TM '<tm>' / Threat '<threat>': duplicate control '<name>'`).

## 0.6.0

### Jul 14, 2026

CHANGES:

* New `ParseHCLRawSet` parses multiple named HCL inputs (`NamedInput`) into
  one parsed set. Each input decodes with its own name so diagnostics point
  at the offending input, and imports, variables and `including` are handled
  per input the same way `ParseHCLFile`/`ParseFile` treat a top-level file —
  relative `including`/import paths resolve against the input's name, so
  names should be real file paths when inputs use either. Set-level
  validation —
  unique names and ids, reserved segments, `extends` resolution — runs once
  over the merged set, so a model may extend a parent declared in another
  input regardless of input order. Unlike single-input parsing, each input
  may carry its own `backend` block (at most one per input); all of them are
  exposed via `GetWrapped().Backends`, and cross-input backend agreement is
  left to the consumer.
* New `SetSkipExtendsResolution` parses without resolving `extends`
  inheritance: an `extends` target missing from the parsed content is not an
  error, and no inherited entities are materialized — the `Extends` field
  stays populated for the consumer to resolve later, so a single file of a
  multi-file set can be parsed file-faithfully. All other validation and
  normalization (per-model checks, risk normalization, control imports, id
  grammar and uniqueness) is unchanged, and the default behavior with
  resolution on is untouched.
* BREAKING: the `backend` block's `segment` attribute (the `BackendSegment`
  field) is removed. It was added in v0.4.0 for a feature that never
  shipped; `segment = "..."` in a backend block is now an "Unsupported
  argument" parse error.

## 0.5.3

### Jul 12, 2026

CHANGES:

* No API changes
* Bumping some of the go deps

## 0.5.2

### Jul 9, 2026

CHANGES:

- No API changes
- Bumping go standard buildchain and other deps

## 0.5.1

### Jul 5, 2026

CHANGES:

- No changes from 0.5.0

## 0.5.0

### Jul 5, 2026

CHANGES:

* `threatmodel` blocks support an optional `id` attribute: a stable,
  identifier-safe handle (`^[a-z][a-z0-9_]*$`, unique within a parsed file)
  that survives renames and lets tooling offer dotted references such as
  `threatmodel.tower_of_london` (threat model names are arbitrary strings, so
  they can't appear in dotted HCL traversals). New API:
  `Threatmodel.Identifier()` returns the declared id or one derived from the
  name; `DeriveIdentifier` exposes the name→identifier derivation (shared
  with OTM export ids); `ValidIdentifier` reports whether a string is
  acceptable as a declared id.
* `threatmodel` ids can be dot-separated identifier segments, namespacing
  models into a hierarchy — `buildings.tower`, `buildings.bridge`,
  `infra.network.vpc`. A model may sit at the namespace itself (`buildings`)
  as the parent of its nested children; the only constraint is that a segment
  directly beneath a parent model's id can't be a threat model field name
  (`buildings.threats` would shadow that model's threats in references). New
  API: `IdentifierPrefixes` returns a dotted id's namespace prefixes,
  `ReservedIdSegment` reports segments that can't sit directly beneath a
  parent model.
* `threatmodel` blocks support an optional `extends` attribute naming another
  model's declared id in the same parsed set. The extending model inherits
  the parent's threats, information assets, use cases, exclusions and
  third-party dependencies (same-named items in the child win) and its
  `attributes` block when the child declares none — the same union-merge
  semantics as `including`, applied by id. Chains resolve parent-first;
  cycles and unknown targets are parse errors. Scalars, DFDs and mermaid
  diagrams deliberately stay per-model.
* Threat model id validation covers the gaps left by the initial `id`
  support: an explicit `id = ""` is now a parse error instead of silently
  behaving as unset (in both HCL and JSON), and `AddTMAndWrite` validates the
  incoming model's declared id (format, and uniqueness against the models it
  already holds) before appending. A new `ValidateUniqueIdentifiers` helper
  checks a slice of threat models — e.g. aggregated across multiple parsed
  files, which parse-time validation never sees together — for
  identifier-safe declared ids and collision-free effective `Identifier()`
  values (declared and derived), for consumers building reference registries.
* Element references now accept identifier-safe slugs alongside exact names.
  Anywhere a threat model refers to another element by name — DFD `flow`
  `from`/`to`, `data_store` `information_asset` links, threat
  `information_asset_refs`, and element `trust_zone` attributes — the
  reference may be the element's slug in either divider form (`"web-app"` or
  `"web_app"` for `"Web App"`). Slugs use the same algorithm as the OTM
  exporter's element ids, now exported as `spec.Slugify` (kebab) and
  `spec.SlugifyUnderscore`. Exact name matches always win; a slug that
  matches more than one element is a validation error. References are
  rewritten to the canonical element name at parse time, so renderers,
  exporters, and round-tripped HCL always see canonical names. Note this also
  means a `trust_zone` attribute that slug-matches a declared `trust_zone`
  block now resolves to that zone instead of creating a separate implicit
  zone.
* References can also be written with dot notation instead of quoted strings:
  `from = process.web_app`, `to = data_store.user_database`,
  `information_asset_refs = [information_asset.customer_data]`, or
  `trust_zone = trust_zone.internal_zone`. Namespaces exist for `process`,
  `external_element`, `data_store`, `information_asset`, and `trust_zone`,
  built from the element labels in the same file; an unknown slug fails at
  parse time. Dotted references use underscore slugs — consistent with the
  `threatmodel` `id` convention, and avoiding the hyphen/subtraction
  ambiguity in bare HCL expressions. Slugs that aren't valid HCL identifiers
  (e.g. starting with a digit) can use index syntax: `process["3rd_party"]`.

SECURITY:

* Remote `imports` / `including` sources (http, https, git, s3, gcs, ...) are
  now disabled by default. Parsing a threat model no longer triggers arbitrary
  network fetches or remote content inclusion unless the operator opts in with
  `allow_remote_imports = true` in their threatcl config. This closes an SSRF /
  remote-fetch vector reachable purely by parsing an untrusted model.
* Local file includes are now contained to the directory of the referring
  file, blocking `file:///etc/passwd` and `../` traversal (including via the
  `repo|subpath` form) from reading arbitrary files off the host.
* When remote imports are enabled, http/https fetches now refuse to connect to
  loopback and link-local addresses (e.g. the `169.254.169.254` cloud metadata
  endpoint).

## 0.4.0

### June 27, 2026

CHANGES:

* Added an optional `segment` attribute to the `backend` block

## 0.3.3

### June 27, 2026

CHANGES:

* Bumped some deps, no direct API/Library changes

## 0.3.2

### Jun 27, 2026

CHANGES:

* No changes - this was a build attestation release only

## 0.3.1

### Jun 14, 2026

CHANGES:

* Added the underlying spec support for LSP implementation

## 0.3.0

### Jun 8, 2026

CHANGES:

* Bumping cleanly to 0.3.0 (feature wise, same as 0.2.9)

## 0.2.9

### Jun 8, 2026

CHANGES:

* Threat models now support an optional top-level `repository` attribute for linking to source code repositories (e.g. GitHub, GitLab). It takes a list of full URLs (scheme included), so a single threat model can reference multiple repositories: `repository = ["https://github.com/org/repo"]`. The value is treated as a free-form list of strings (consistent with `link`/`diagram_link`), is inherited by including threat models when not otherwise set, renders as a `## Repositories` section in Markdown, and is emitted under `project.attributes.repository` when exporting to OTM.
* `threat` blocks now support an optional `risk` block for rating a threat. It takes a required `likelihood` and `impact` (ordinal enums: `very_low`, `low`, `medium`, `high`, `very_high`), an optional `rationale`, and an optional `severity` override; by default `severity` is computed from a built-in likelihood×impact matrix. The tool also derives an inherent score and a residual score/severity that factors in the `risk_reduction` of implemented controls, and maps `likelihood`/`impact` onto the threat's `risk` object when exporting to OTM.

## 0.2.8

### Jun 6, 2026

CHANGES:

* Threat models now support a top-level `mermaid` block for embedding free-form mermaid diagrams. Each block takes a title label, a required `content` attribute (the raw mermaid source, idiomatically a heredoc), and an optional `description`. Multiple `mermaid` blocks are allowed per threat model, mirroring `data_flow_diagram_v2`. The diagram type is inferred by mermaid from the first line of `content`, so there is no `type`/`engine` attribute.

## 0.2.7

### May 28, 2026

CHANGES:

* Information Asset blocks now support an optional ref attribute

## 0.2.6

### May 24, 2026

CHANGES:

* Fixed `HclString()` round-tripping: `[]*Struct` fields tagged `hcl:"...,block"` (such as nested `control` blocks inside a `threat`) now emit proper repeated block syntax instead of degrading to a list-of-objects attribute (`control = [{...}]`). The previous output did not parse back as a valid threat model.
* Round-tripped HCL no longer emits noise for zero-valued optional fields (`imports = null`, `created_at = 0`, `stride = []`, etc.).
* `ExpandedControls` is cleared during HCL emission to avoid duplicating controls that were merged into `Controls` at parse time.

## 0.2.5

### May 16, 2026

CHANGES:

* DFD's can now have multiple `flow` blocks in the same direction
* DFD Flow's now have an optional `protocol` attribute
* DFD rendering supports various rendering options, currently targeting the protocol rendering. By default, `protocol` will be appended to a flow's label. But can also be color-coded, none, or both.
* DFD rendering now supports outputting in mermaid and d2 text
* DFD rendering to DOT and SVG/PNG no longer depends on CGO

## 0.2.4

### Jan 11, 2026

CHANGES:

* Now with backend block and ref attributes

## 0.2.3

### Dec 24, 2025

CHANGES:

* Threats are validated to have unique names, not descriptions

## 0.2.2

### Dec 24, 2025

CHANGES:

* Minor tweak to MD output to use Threat name
* Introduced version bumping script

## 0.2.1

### Dec 24, 2025

CHANGES:

* Fixing a panic error

## 0.2.0

### Dec 23, 2025

CHANGES:

* Major version update to support the following:
    * Split DFD CGO requirements
    * Threats have names
    * Expanded controls are just `control`

## 0.1.16

### Dec 3, 2025

CHANGES:

* Minor tweaks to deprecate ioutil and suppress some excessive logging

## 0.1.15

### Oct 13, 2025

CHANGES:

* When generating a string version of the HCL, after processing, remove `control_imports`

## 0.1.14

### Oct 4, 2025

CHANGES:

* Updated spec to 0.1.14
* Added a CHANGELOG file
* Added a CONTRIBUTING file
