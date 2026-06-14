package lang

import (
	"strings"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"
)

// slotKind classifies what the cursor is positioned to type.
type slotKind int

const (
	// slotBlockOrAttr is a body position where either a nested block or an
	// attribute name is valid (the common case; editors filter by prefix).
	slotBlockOrAttr slotKind = iota
	// slotAttrValue is the right-hand side of an `attr = ...` assignment.
	slotAttrValue
)

// cursorContext is the resolved meaning of a cursor position: which body it is
// in (and that body's schema and block path from the root), plus which slot is
// being edited.
type cursorContext struct {
	body     *hclsyntax.Body
	schema   *BodySchema
	path     []string
	slot     slotKind
	attrName string // set when slot == slotAttrValue
}

// resolveContext descends the AST to the innermost block body containing pos,
// then classifies the slot from the current line's text. The AST descent is
// robust to a half-typed current line because the *enclosing* block is usually
// still well-formed; the line-text classification handles the broken line.
func resolveContext(pf *ParsedFile, pos hcl.Pos) cursorContext {
	body := pf.Body
	schema := Schema()
	var path []string

	for {
		descended := false
		for _, blk := range body.Blocks {
			if !insideBlockBody(blk, len(pf.Src), pos.Byte) {
				continue
			}
			if child := findBlockSchema(schema, blk.Type); child != nil {
				schema = &child.Body
			} else {
				schema = &BodySchema{} // unknown block: no candidates from here
			}
			body = blk.Body
			path = append(path, blk.Type)
			descended = true
			break
		}
		if !descended {
			break
		}
	}

	ctx := cursorContext{body: body, schema: schema, path: path, slot: slotBlockOrAttr}
	if name, ok := attrValueSlot(linePrefix(pf.Src, pos.Byte)); ok {
		ctx.slot = slotAttrValue
		ctx.attrName = name
	}
	return ctx
}

// insideBlockBody reports whether byteOff falls between a block's braces. If the
// block has no recovered closing brace (mid-edit at EOF), the body is treated as
// extending to the end of the source.
func insideBlockBody(blk *hclsyntax.Block, srcLen, byteOff int) bool {
	start := blk.OpenBraceRange.End.Byte
	end := blk.CloseBraceRange.Start.Byte
	if end <= start {
		end = srcLen
	}
	return byteOff >= start && byteOff <= end
}

// linePrefix returns the text of the current line from its start up to byteOff.
func linePrefix(src []byte, byteOff int) string {
	if byteOff > len(src) {
		byteOff = len(src)
	}
	if byteOff < 0 {
		byteOff = 0
	}
	start := byteOff
	for start > 0 && src[start-1] != '\n' {
		start--
	}
	return string(src[start:byteOff])
}

// attrValueSlot reports whether the line prefix puts the cursor on the value
// side of an `attr = ...` assignment, and if so returns the attribute name.
func attrValueSlot(prefix string) (string, bool) {
	lhs, _, found := strings.Cut(prefix, "=")
	if !found {
		return "", false
	}
	name := strings.TrimSpace(lhs)
	if name == "" {
		return "", false
	}
	return name, true
}
