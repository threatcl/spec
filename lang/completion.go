package lang

import (
	"fmt"
	"strings"

	"github.com/hashicorp/hcl/v2"
)

// CompletionsAt returns context-aware completion candidates for the cursor at
// pos. In an attribute-value slot it offers that attribute's enum values (if
// any); otherwise it offers the blocks and attributes valid in the current
// body. Editors filter the combined block/attribute list by the typed prefix.
func CompletionsAt(pf *ParsedFile, pos hcl.Pos) []Candidate {
	if pf == nil || pf.Body == nil {
		return nil
	}
	ctx := resolveContext(pf, pos)

	if ctx.slot == slotAttrValue {
		return enumCandidates(ctx.schema, ctx.attrName)
	}

	candidates := make([]Candidate, 0, len(ctx.schema.Blocks)+len(ctx.schema.Attrs))
	candidates = append(candidates, blockCandidates(ctx.schema)...)
	candidates = append(candidates, attrCandidates(ctx.schema)...)
	return candidates
}

func enumCandidates(schema *BodySchema, attrName string) []Candidate {
	as := findAttrSchema(schema, attrName)
	if as == nil || len(as.EnumValues) == 0 {
		return nil
	}
	out := make([]Candidate, 0, len(as.EnumValues))
	for _, v := range as.EnumValues {
		out = append(out, Candidate{
			Label:  v,
			Detail: "value of " + attrName,
			Doc:    as.Doc,
			Kind:   CandidateKindEnumMember,
		})
	}
	return out
}

func blockCandidates(schema *BodySchema) []Candidate {
	out := make([]Candidate, 0, len(schema.Blocks))
	for _, b := range schema.Blocks {
		out = append(out, Candidate{
			Label:      b.Type,
			Detail:     blockDetail(b),
			Doc:        b.Doc,
			InsertText: blockSnippet(b),
			Kind:       CandidateKindSnippet,
		})
	}
	return out
}

func attrCandidates(schema *BodySchema) []Candidate {
	out := make([]Candidate, 0, len(schema.Attrs))
	for _, a := range schema.Attrs {
		detail := a.Type
		if a.Required {
			detail += ", required"
		}
		out = append(out, Candidate{
			Label:      a.Name,
			Detail:     detail,
			Doc:        a.Doc,
			InsertText: a.Name + " = ",
			Kind:       CandidateKindField,
		})
	}
	return out
}

func blockDetail(b BlockSchema) string {
	if len(b.Labels) == 0 {
		return "block"
	}
	return "block " + strings.Join(b.Labels, " ")
}

// blockSnippet builds an LSP snippet (with ${n:placeholder} tab stops and a
// final $0) scaffolding the block with its labels and braces. The CLI passes
// the placeholders through as an LSP snippet; non-snippet clients still get
// sensible literal-ish text.
func blockSnippet(b BlockSchema) string {
	var sb strings.Builder
	sb.WriteString(b.Type)
	for i, lbl := range b.Labels {
		fmt.Fprintf(&sb, " \"${%d:%s}\"", i+1, lbl)
	}
	sb.WriteString(" {\n\t$0\n}")
	return sb.String()
}
