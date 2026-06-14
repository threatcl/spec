package lang

import (
	"strings"

	"github.com/hashicorp/hcl/v2/hclsyntax"
)

// Symbols returns the document outline: a tree of blocks (threatmodel → threat
// / control / data flow diagram / ...). Attributes are intentionally omitted to
// keep the outline navigable. The label (when present) is used as the symbol
// name; the block type is the detail.
func Symbols(pf *ParsedFile) []Symbol {
	if pf == nil || pf.Body == nil {
		return nil
	}
	return symbolsForBody(pf.Body, Schema())
}

func symbolsForBody(body *hclsyntax.Body, schema *BodySchema) []Symbol {
	var syms []Symbol
	for _, blk := range body.Blocks {
		child := findBlockSchema(schema, blk.Type)

		sym := Symbol{
			Name:           symbolName(blk),
			Detail:         blk.Type,
			Kind:           symbolKind(blk.Type),
			Range:          blk.Range(),
			SelectionRange: blk.DefRange(),
		}
		if child != nil {
			sym.Children = symbolsForBody(blk.Body, &child.Body)
		}
		syms = append(syms, sym)
	}
	return syms
}

// symbolName uses the block's labels (joined) as the display name, falling back
// to the block type for label-less blocks (attributes, usecase, exclusion, ...).
func symbolName(blk *hclsyntax.Block) string {
	if len(blk.Labels) == 0 {
		return blk.Type
	}
	return strings.Join(blk.Labels, " ")
}

func symbolKind(blockType string) SymbolKind {
	if blockType == "threatmodel" {
		return SymbolKindNamespace
	}
	return SymbolKindStruct
}
