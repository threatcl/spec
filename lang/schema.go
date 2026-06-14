package lang

import (
	"github.com/hashicorp/hcl/v2"
	"github.com/threatcl/spec"
)

// CandidateKind classifies a completion candidate so the CLI can map it onto an
// LSP CompletionItemKind without re-deriving intent.
type CandidateKind int

const (
	// CandidateKindKeyword is a bare keyword (e.g. a block type with no body
	// snippet).
	CandidateKindKeyword CandidateKind = iota
	// CandidateKindField is an attribute name.
	CandidateKindField
	// CandidateKindEnumMember is one allowed value of an enum-ish attribute.
	CandidateKindEnumMember
	// CandidateKindSnippet is a block scaffold inserted with its braces.
	CandidateKindSnippet
)

// SymbolKind classifies a document-outline symbol.
type SymbolKind int

const (
	// SymbolKindNamespace is a container-ish block (threatmodel).
	SymbolKindNamespace SymbolKind = iota
	// SymbolKindStruct is a structural block (threat, control, dfd, ...).
	SymbolKindStruct
	// SymbolKindField is an attribute.
	SymbolKindField
)

// Candidate is a neutral completion suggestion. InsertText, when non-empty, is
// what should be inserted (it may contain LSP snippet placeholders that the CLI
// passes through); otherwise Label is inserted verbatim.
type Candidate struct {
	Label      string
	Detail     string
	Doc        string
	InsertText string
	Kind       CandidateKind
}

// Hover is the documentation for the symbol under a cursor, plus the source
// range it applies to.
type Hover struct {
	Contents string
	Range    hcl.Range
}

// Symbol is one node of the document outline.
type Symbol struct {
	Name           string
	Detail         string
	Kind           SymbolKind
	Range          hcl.Range
	SelectionRange hcl.Range
	Children       []Symbol
}

// AttrSchema describes a single attribute: its name, a doc string (authored
// here, reused by hover and completion detail), whether HCL requires it, a
// human-readable type hint, and — for enum-ish attributes — the allowed values.
type AttrSchema struct {
	Name       string
	Doc        string
	Required   bool
	Type       string
	EnumValues []string
}

// BlockSchema describes a block type: its keyword, label names, doc, whether it
// may repeat in its parent, and its own body.
type BlockSchema struct {
	Type       string
	Labels     []string
	Doc        string
	Repeatable bool
	Body       BodySchema
}

// BodySchema is the set of blocks and attributes valid in a given body.
type BodySchema struct {
	Blocks []BlockSchema
	Attrs  []AttrSchema
}

// Schema returns the root schema for a threatcl document (the body of a
// ThreatmodelWrapped), hand-authored from the spec struct tags and kept honest
// by the reflection drift guard in schema_test.go. Enum value sets are seeded
// from the built-in spec defaults; a future SchemaWithConfig could layer an
// hcltmrc override on top without changing this signature.
func Schema() *BodySchema {
	cfg, _ := spec.LoadSpecConfig() // built-in defaults; never errors

	return &BodySchema{
		Attrs: []AttrSchema{
			{Name: "spec_version", Doc: "The threatcl spec version this file targets.", Type: "string"},
		},
		Blocks: []BlockSchema{
			threatmodelBlock(cfg),
			componentBlock(),
			variableBlock(),
			backendBlock(),
		},
	}
}

func threatmodelBlock(cfg *spec.ThreatmodelSpecConfig) BlockSchema {
	return BlockSchema{
		Type:       "threatmodel",
		Labels:     []string{"name"},
		Doc:        "A single threat model. The label is its unique name.",
		Repeatable: true,
		Body: BodySchema{
			Attrs: []AttrSchema{
				{Name: "author", Required: true, Type: "string", Doc: "Who authored this threat model."},
				{Name: "description", Type: "string", Doc: "Free-text description of the system being modelled."},
				{Name: "link", Type: "string", Doc: "A URL with more detail about this system."},
				{Name: "diagram_link", Type: "string", Doc: "A URL to an externally-hosted diagram."},
				{Name: "repository", Type: "list(string)", Doc: "Source code repositories this model covers (full URLs)."},
				{Name: "imports", Type: "list(string)", Doc: "Remote sources to import reusable components/controls from."},
				{Name: "including", Type: "string", Doc: "A single remote threat model to merge into this one."},
				{Name: "created_at", Type: "number", Doc: "Unix timestamp this model was created."},
				{Name: "updated_at", Type: "number", Doc: "Unix timestamp this model was last updated."},
			},
			Blocks: []BlockSchema{
				{
					Type:       "attributes",
					Doc:        "Coarse attributes describing the initiative.",
					Repeatable: false,
					Body: BodySchema{Attrs: []AttrSchema{
						{Name: "new_initiative", Required: true, Type: "bool", Doc: "Whether this is a new initiative."},
						{Name: "internet_facing", Required: true, Type: "bool", Doc: "Whether the system is internet-facing."},
						{Name: "initiative_size", Required: true, Type: "string", EnumValues: cfg.InitiativeSizes, Doc: "Relative size of the initiative."},
					}},
				},
				{
					Type:       "additional_attribute",
					Labels:     []string{"name"},
					Doc:        "A free-form name/value attribute.",
					Repeatable: true,
					Body: BodySchema{Attrs: []AttrSchema{
						{Name: "value", Required: true, Type: "string", Doc: "The attribute's value."},
					}},
				},
				{
					Type:       "information_asset",
					Labels:     []string{"name"},
					Doc:        "A data asset handled by the system.",
					Repeatable: true,
					Body: BodySchema{Attrs: []AttrSchema{
						{Name: "description", Type: "string", Doc: "What this asset is."},
						{Name: "information_classification", Type: "string", EnumValues: cfg.InfoClassifications, Doc: "Sensitivity classification of the asset."},
						{Name: "source", Type: "string", Doc: "Where this asset originates."},
						{Name: "ref", Type: "string", Doc: "An external reference id for this asset."},
					}},
				},
				threatBlock(cfg),
				{
					Type:       "usecase",
					Doc:        "An intended use case for the system.",
					Repeatable: true,
					Body: BodySchema{Attrs: []AttrSchema{
						{Name: "description", Required: true, Type: "string", Doc: "Description of the use case."},
					}},
				},
				{
					Type:       "exclusion",
					Doc:        "Something explicitly out of scope for this model.",
					Repeatable: true,
					Body: BodySchema{Attrs: []AttrSchema{
						{Name: "description", Required: true, Type: "string", Doc: "Description of the exclusion."},
					}},
				},
				{
					Type:       "third_party_dependency",
					Labels:     []string{"name"},
					Doc:        "An external dependency the system relies on.",
					Repeatable: true,
					Body: BodySchema{Attrs: []AttrSchema{
						{Name: "description", Required: true, Type: "string", Doc: "What the dependency is."},
						{Name: "uptime_dependency", Required: true, Type: "string", EnumValues: cfg.UptimeDepClassifications, Doc: "How much the system's uptime depends on this."},
						{Name: "saas", Type: "bool", Doc: "Whether the dependency is SaaS."},
						{Name: "paying_customer", Type: "bool", Doc: "Whether we are a paying customer."},
						{Name: "open_source", Type: "bool", Doc: "Whether the dependency is open source."},
						{Name: "infrastructure", Type: "bool", Doc: "Whether the dependency is infrastructure."},
						{Name: "uptime_notes", Type: "string", Doc: "Notes about the uptime dependency."},
					}},
				},
				dfdBlock("data_flow_diagram_v2", []string{"name"}, "A data flow diagram (v2). The label is its title.", true),
				{
					Type:       "mermaid",
					Labels:     []string{"name"},
					Doc:        "An embedded free-form mermaid diagram. The label is its title.",
					Repeatable: true,
					Body: BodySchema{Attrs: []AttrSchema{
						{Name: "content", Required: true, Type: "string", Doc: "Raw mermaid source (idiomatically a heredoc)."},
						{Name: "description", Type: "string", Doc: "Description of the diagram."},
					}},
				},
				dfdBlock("data_flow_diagram", nil, "Deprecated legacy data flow diagram. Prefer data_flow_diagram_v2.", false),
			},
		},
	}
}

func threatBlock(cfg *spec.ThreatmodelSpecConfig) BlockSchema {
	return BlockSchema{
		Type:       "threat",
		Labels:     []string{"name"},
		Doc:        "A threat against the system.",
		Repeatable: true,
		Body: BodySchema{
			Attrs: []AttrSchema{
				{Name: "description", Required: true, Type: "string", Doc: "Description of the threat."},
				{Name: "impacts", Type: "list(string)", EnumValues: cfg.ImpactTypes, Doc: "Which security properties this threat impacts."},
				{Name: "stride", Type: "list(string)", EnumValues: cfg.STRIDE, Doc: "STRIDE categories this threat falls under."},
				{Name: "information_asset_refs", Type: "list(string)", Doc: "Names of information_assets this threat affects."},
				{Name: "control_imports", Type: "list(string)", Doc: "References to imported controls (import.control.NAME)."},
				{Name: "control", Type: "string", Doc: "Deprecated free-text control. Prefer a control block."},
				{Name: "ref", Type: "string", Doc: "An external reference id for this threat."},
			},
			Blocks: []BlockSchema{
				riskBlock(),
				controlBlock("control", "A control mitigating this threat."),
				controlBlock("expanded_control", "Deprecated alias for a control block."),
				{
					Type:       "proposed_control",
					Doc:        "Deprecated proposed control. Prefer a control block.",
					Repeatable: true,
					Body: BodySchema{Attrs: []AttrSchema{
						{Name: "description", Required: true, Type: "string", Doc: "Description of the proposed control."},
						{Name: "implemented", Type: "bool", Doc: "Whether the control is implemented."},
					}},
				},
			},
		},
	}
}

func riskBlock() BlockSchema {
	return BlockSchema{
		Type:       "risk",
		Doc:        "An optional, methodology-neutral risk rating for this threat.",
		Repeatable: false,
		Body: BodySchema{Attrs: []AttrSchema{
			{Name: "likelihood", Required: true, Type: "string", EnumValues: spec.RiskLevels, Doc: "How likely the threat is (ordinal enum)."},
			{Name: "impact", Required: true, Type: "string", EnumValues: spec.RiskLevels, Doc: "How impactful the threat is (ordinal enum)."},
			{Name: "severity", Type: "string", EnumValues: spec.SeverityLevels, Doc: "Optional severity override; otherwise computed from likelihood×impact."},
			{Name: "rationale", Type: "string", Doc: "Free-text rationale for the rating."},
		}},
	}
}

// controlBlock builds the schema for a control-style block (used by both
// `control` and the deprecated `expanded_control`, which share the Control
// struct).
func controlBlock(typeName, doc string) BlockSchema {
	return BlockSchema{
		Type:       typeName,
		Labels:     []string{"name"},
		Doc:        doc,
		Repeatable: true,
		Body: BodySchema{
			Attrs: []AttrSchema{
				{Name: "description", Required: true, Type: "string", Doc: "Description of the control."},
				{Name: "implemented", Type: "bool", Doc: "Whether the control is implemented."},
				{Name: "implementation_notes", Type: "string", Doc: "Notes about the implementation."},
				{Name: "risk_reduction", Type: "number", Doc: "Percentage by which this control reduces risk."},
				{Name: "ref", Type: "string", Doc: "An external reference id for this control."},
			},
			Blocks: []BlockSchema{controlAttributeBlock()},
		},
	}
}

func controlAttributeBlock() BlockSchema {
	return BlockSchema{
		Type:       "attribute",
		Labels:     []string{"name"},
		Doc:        "A free-form name/value attribute of the control.",
		Repeatable: true,
		Body: BodySchema{Attrs: []AttrSchema{
			{Name: "value", Required: true, Type: "string", Doc: "The attribute's value."},
		}},
	}
}

// dfdBlock builds the schema for a data flow diagram body. Both the v2 block and
// the legacy block share an identical body (process/external_element/data_store/
// flow/trust_zone blocks plus an optional import attribute); they differ only in
// keyword, label, and whether they repeat.
func dfdBlock(typeName string, labels []string, doc string, repeatable bool) BlockSchema {
	return BlockSchema{
		Type:       typeName,
		Labels:     labels,
		Doc:        doc,
		Repeatable: repeatable,
		Body: BodySchema{
			Attrs: []AttrSchema{
				{Name: "import", Type: "string", Doc: "Import diagram elements from another file."},
			},
			Blocks: append(dfdElementBlocks(), []BlockSchema{
				{
					Type:       "flow",
					Labels:     []string{"name"},
					Doc:        "A data flow between two elements.",
					Repeatable: true,
					Body: BodySchema{Attrs: []AttrSchema{
						{Name: "from", Required: true, Type: "string", Doc: "Name of the source element."},
						{Name: "to", Required: true, Type: "string", Doc: "Name of the destination element."},
						{Name: "protocol", Type: "string", Doc: "Protocol used for the flow."},
					}},
				},
				{
					Type:       "trust_zone",
					Labels:     []string{"name"},
					Doc:        "A trust boundary grouping diagram elements.",
					Repeatable: true,
					Body:       BodySchema{Blocks: dfdElementBlocks()},
				},
			}...),
		},
	}
}

// dfdElementBlocks returns the process/external_element/data_store blocks shared
// by data flow diagram bodies and trust_zone bodies.
func dfdElementBlocks() []BlockSchema {
	return []BlockSchema{
		{
			Type:       "process",
			Labels:     []string{"name"},
			Doc:        "A process element.",
			Repeatable: true,
			Body: BodySchema{Attrs: []AttrSchema{
				{Name: "trust_zone", Type: "string", Doc: "Trust zone this element belongs to."},
			}},
		},
		{
			Type:       "external_element",
			Labels:     []string{"name"},
			Doc:        "An external entity.",
			Repeatable: true,
			Body: BodySchema{Attrs: []AttrSchema{
				{Name: "trust_zone", Type: "string", Doc: "Trust zone this element belongs to."},
			}},
		},
		{
			Type:       "data_store",
			Labels:     []string{"name"},
			Doc:        "A data store element.",
			Repeatable: true,
			Body: BodySchema{Attrs: []AttrSchema{
				{Name: "trust_zone", Type: "string", Doc: "Trust zone this element belongs to."},
				{Name: "information_asset", Type: "string", Doc: "Name of a linked information_asset."},
			}},
		},
	}
}

func componentBlock() BlockSchema {
	return BlockSchema{
		Type:       "component",
		Labels:     []string{"component_type", "component_name"},
		Doc:        "A reusable component (e.g. a control) importable by other models.",
		Repeatable: true,
		Body: BodySchema{
			Attrs: []AttrSchema{
				{Name: "description", Required: true, Type: "string", Doc: "Description of the component."},
				{Name: "implemented", Type: "bool", Doc: "Whether the component is implemented."},
				{Name: "implementation_notes", Type: "string", Doc: "Notes about the implementation."},
				{Name: "risk_reduction", Type: "number", Doc: "Percentage by which this component reduces risk."},
			},
			Blocks: []BlockSchema{controlAttributeBlock()},
		},
	}
}

func variableBlock() BlockSchema {
	return BlockSchema{
		Type:       "variable",
		Labels:     []string{"variable_name"},
		Doc:        "A reusable variable referenced as var.NAME.",
		Repeatable: true,
		Body: BodySchema{Attrs: []AttrSchema{
			{Name: "value", Required: true, Type: "string", Doc: "The variable's value."},
		}},
	}
}

func backendBlock() BlockSchema {
	return BlockSchema{
		Type:       "backend",
		Labels:     []string{"backend_name"},
		Doc:        "Backend configuration for syncing this model.",
		Repeatable: true,
		Body: BodySchema{Attrs: []AttrSchema{
			{Name: "organization", Required: true, Type: "string", Doc: "Backend organization."},
			{Name: "threatmodel", Type: "string", Doc: "Backend threatmodel short name."},
			{Name: "project", Type: "string", Doc: "Backend project."},
		}},
	}
}
