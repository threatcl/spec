package lang

import (
	"strings"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"
)

// HoverAt returns documentation for the schema symbol under the cursor — an
// attribute name or a block type keyword — or nil if the cursor isn't on a
// documented symbol.
func HoverAt(pf *ParsedFile, pos hcl.Pos) *Hover {
	if pf == nil || pf.Body == nil {
		return nil
	}
	return hoverInBody(pf.Body, Schema(), pos, len(pf.Src))
}

func hoverInBody(body *hclsyntax.Body, schema *BodySchema, pos hcl.Pos, srcLen int) *Hover {
	for _, attr := range body.Attributes {
		if attr.NameRange.ContainsPos(pos) {
			if as := findAttrSchema(schema, attr.Name); as != nil {
				return &Hover{Contents: attrHoverText(as), Range: attr.NameRange}
			}
			return nil
		}
	}

	for _, blk := range body.Blocks {
		child := findBlockSchema(schema, blk.Type)
		if blk.TypeRange.ContainsPos(pos) {
			if child != nil {
				return &Hover{Contents: blockHoverText(child), Range: blk.TypeRange}
			}
			return nil
		}
		if child != nil && insideBlockBody(blk, srcLen, pos.Byte) {
			return hoverInBody(blk.Body, &child.Body, pos, srcLen)
		}
	}
	return nil
}

func attrHoverText(a *AttrSchema) string {
	var sb strings.Builder
	sb.WriteString("**" + a.Name + "**")
	if a.Type != "" {
		sb.WriteString(" (" + a.Type)
		if a.Required {
			sb.WriteString(", required")
		}
		sb.WriteString(")")
	}
	if a.Doc != "" {
		sb.WriteString("\n\n" + a.Doc)
	}
	if len(a.EnumValues) > 0 {
		sb.WriteString("\n\nAllowed values: " + strings.Join(a.EnumValues, ", "))
	}
	return sb.String()
}

func blockHoverText(b *BlockSchema) string {
	var sb strings.Builder
	sb.WriteString("**" + b.Type + "** block")
	if len(b.Labels) > 0 {
		sb.WriteString(" (" + strings.Join(b.Labels, ", ") + ")")
	}
	if b.Doc != "" {
		sb.WriteString("\n\n" + b.Doc)
	}
	return sb.String()
}
