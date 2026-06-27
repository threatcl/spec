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
