package lang

import (
	"fmt"
	"slices"
	"sort"
	"strings"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/zclconf/go-cty/cty"
)

// Diagnostics returns the union of syntax, structural (schema), and semantic
// (enum) problems for a threatcl document, each carrying an hcl.Range. It is
// error-tolerant: it never bails on the first problem, so an editor gets a full
// list on every keystroke.
//
// The three layers, all collecting (never gating on HasErrors):
//
//  1. Syntax — malformed HCL, from hclsyntax via ParseSource.
//  2. Structural — unknown blocks/attributes and missing required attributes,
//     computed with hcl.Body.Content against the schema. Content does NOT
//     evaluate expressions, so var.* / import.* references never produce false
//     positives here (and no remote import is ever fetched).
//  3. Semantic — invalid enum values (risk likelihood/impact/severity are
//     errors; stride/impacts/classification/initiative_size/uptime_dependency
//     are warnings), checked directly against the AST so they pinpoint the
//     offending value.
//
// Deliberately out of scope for v1: range-mapping the full ValidateTm
// multierror (duplicate names, information_asset reference existence, DFD flow
// wiring). Those plain-string errors are keyed on names/descriptions rather
// than positions; precise mapping is deferred.
func Diagnostics(filename string, src []byte) hcl.Diagnostics {
	pf, syntaxDiags := ParseSource(filename, src)

	out := make(hcl.Diagnostics, 0, len(syntaxDiags))
	out = append(out, syntaxDiags...)

	if pf.Body != nil {
		root := Schema()
		out = append(out, structuralDiags(pf.Body, root)...)
		out = append(out, enumDiags(pf.Body, root)...)
	}

	sortDiags(out)
	return out
}

// structuralDiags recursively checks a body against a schema using
// hcl.Body.Content, descending into every block whose type is known.
func structuralDiags(body *hclsyntax.Body, bs *BodySchema) hcl.Diagnostics {
	content, diags := body.Content(toHCLSchema(bs))

	// Content returns the matched blocks even alongside diagnostics, so we can
	// still descend into the known ones.
	for _, blk := range content.Blocks {
		child := findBlockSchema(bs, blk.Type)
		if child == nil {
			continue
		}
		if sub, ok := blk.Body.(*hclsyntax.Body); ok {
			diags = append(diags, structuralDiags(sub, &child.Body)...)
		}
	}
	return diags
}

// enumDiags recursively validates enum-ish attribute values against the schema.
func enumDiags(body *hclsyntax.Body, bs *BodySchema) hcl.Diagnostics {
	var diags hcl.Diagnostics

	for _, attr := range body.Attributes {
		as := findAttrSchema(bs, attr.Name)
		if as == nil || len(as.EnumValues) == 0 {
			continue
		}
		diags = append(diags, checkEnumAttr(attr, as)...)
	}

	for _, blk := range body.Blocks {
		child := findBlockSchema(bs, blk.Type)
		if child == nil {
			continue
		}
		diags = append(diags, enumDiags(blk.Body, &child.Body)...)
	}
	return diags
}

// checkEnumAttr validates a single attribute's literal value(s) against an
// enum. References (var.*, import.*) and non-string values are skipped rather
// than reported — they aren't statically resolvable here.
func checkEnumAttr(attr *hclsyntax.Attribute, as *AttrSchema) hcl.Diagnostics {
	var diags hcl.Diagnostics

	if as.Type == "list(string)" {
		elems, listDiags := hcl.ExprList(attr.Expr)
		if listDiags.HasErrors() {
			return nil // not a literal list; leave it to other layers
		}
		for _, el := range elems {
			if s, ok := stringValue(el); ok && !enumValid(attr.Name, s, as.EnumValues) {
				diags = append(diags, enumDiag(attr.Name, s, as.EnumValues, el.Range()))
			}
		}
		return diags
	}

	if s, ok := stringValue(attr.Expr); ok && !enumValid(attr.Name, s, as.EnumValues) {
		diags = append(diags, enumDiag(attr.Name, s, as.EnumValues, attr.Expr.Range()))
	}
	return diags
}

// stringValue evaluates expr with no context and returns its string value if it
// is a known, non-null string literal.
func stringValue(expr hcl.Expression) (string, bool) {
	v, diags := expr.Value(nil)
	if diags.HasErrors() || v.IsNull() || v.Type() != cty.String {
		return "", false
	}
	return v.AsString(), true
}

// enumValid reports whether got is an acceptable value for the named enum
// attribute, mirroring how the spec parser normalises each one: risk
// likelihood/impact/severity fold spaces and hyphens to underscores; the
// remaining enums are matched case-insensitively (the parser title-cases them).
func enumValid(attrName, got string, allowed []string) bool {
	switch attrName {
	case "likelihood", "impact", "severity":
		return slices.Contains(allowed, canonicalRiskToken(got))
	default:
		g := strings.TrimSpace(got)
		for _, a := range allowed {
			if strings.EqualFold(g, a) {
				return true
			}
		}
		return false
	}
}

// canonicalRiskToken reimplements the spec package's (unexported) risk token
// normaliser so this package needs no change to the root spec surface:
// lowercase, trim, and collapse spaces/hyphens to single underscores.
func canonicalRiskToken(in string) string {
	s := strings.ToLower(strings.TrimSpace(in))
	s = strings.ReplaceAll(s, "-", "_")
	s = strings.ReplaceAll(s, " ", "_")
	for strings.Contains(s, "__") {
		s = strings.ReplaceAll(s, "__", "_")
	}
	return s
}

// enumDiag builds the diagnostic for an invalid enum value. Risk
// likelihood/impact/severity are hard errors (the spec parser rejects them);
// the rest are warnings (the parser silently drops/defaults them, but flagging
// is more helpful in an editor).
func enumDiag(attrName, got string, allowed []string, rng hcl.Range) *hcl.Diagnostic {
	d := &hcl.Diagnostic{
		Severity: hcl.DiagWarning,
		Summary:  fmt.Sprintf("Unknown %s value", attrName),
		Detail:   fmt.Sprintf("%q is not a recognised %s value (expected one of: %s)", got, attrName, strings.Join(allowed, ", ")),
		Subject:  rng.Ptr(),
	}
	switch attrName {
	case "likelihood", "impact", "severity":
		d.Severity = hcl.DiagError
		d.Summary = fmt.Sprintf("Invalid risk %s", attrName)
		d.Detail = fmt.Sprintf("%q is not a valid risk %s (expected one of: %s)", got, attrName, strings.Join(allowed, ", "))
	}
	return d
}

// toHCLSchema projects a lang BodySchema onto the hcl.BodySchema that Content
// needs (names, required-ness, and block label arity only).
func toHCLSchema(bs *BodySchema) *hcl.BodySchema {
	hs := &hcl.BodySchema{
		Attributes: make([]hcl.AttributeSchema, 0, len(bs.Attrs)),
		Blocks:     make([]hcl.BlockHeaderSchema, 0, len(bs.Blocks)),
	}
	for _, a := range bs.Attrs {
		hs.Attributes = append(hs.Attributes, hcl.AttributeSchema{Name: a.Name, Required: a.Required})
	}
	for _, b := range bs.Blocks {
		hs.Blocks = append(hs.Blocks, hcl.BlockHeaderSchema{Type: b.Type, LabelNames: b.Labels})
	}
	return hs
}

func findBlockSchema(bs *BodySchema, typ string) *BlockSchema {
	for i := range bs.Blocks {
		if bs.Blocks[i].Type == typ {
			return &bs.Blocks[i]
		}
	}
	return nil
}

func findAttrSchema(bs *BodySchema, name string) *AttrSchema {
	for i := range bs.Attrs {
		if bs.Attrs[i].Name == name {
			return &bs.Attrs[i]
		}
	}
	return nil
}

// sortDiags orders diagnostics by file then byte offset so output is
// deterministic and reads top-to-bottom in an editor.
func sortDiags(diags hcl.Diagnostics) {
	sort.SliceStable(diags, func(i, j int) bool {
		return diagBefore(diags[i], diags[j])
	})
}

func diagBefore(a, b *hcl.Diagnostic) bool {
	ar, br := a.Subject, b.Subject
	switch {
	case ar == nil && br == nil:
		return false
	case ar == nil: // position-less diagnostics sort first
		return true
	case br == nil:
		return false
	}
	if ar.Filename != br.Filename {
		return ar.Filename < br.Filename
	}
	return ar.Start.Byte < br.Start.Byte
}
