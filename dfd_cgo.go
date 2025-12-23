//go:build cgo

package spec

import (
	"bytes"
	"os"

	"github.com/goccy/go-graphviz"
)

func dotToPngBytes(raw []byte) ([]byte, error) {
	g, err := graphviz.ParseBytes(raw)
	if err != nil {
		return nil, err
	}

	out := graphviz.New()
	var buf bytes.Buffer
	if err := out.Render(g, graphviz.PNG, &buf); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func dotToPng(raw []byte, file string) error {
	pngBytes, err := dotToPngBytes(raw)
	if err != nil {
		return err
	}
	return os.WriteFile(file, pngBytes, 0644)
}

func dotToSvgBytes(raw []byte) ([]byte, error) {
	g, err := graphviz.ParseBytes(raw)
	if err != nil {
		return nil, err
	}

	out := graphviz.New()
	var buf bytes.Buffer
	if err := out.Render(g, graphviz.SVG, &buf); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func dotToSvg(raw []byte, file string) error {
	svgBytes, err := dotToSvgBytes(raw)
	if err != nil {
		return err
	}
	return os.WriteFile(file, svgBytes, 0644)
}
