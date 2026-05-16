package spec

import (
	"bytes"
	"context"
	"os"

	"github.com/goccy/go-graphviz"
)

func render(raw []byte, format graphviz.Format) ([]byte, error) {
	ctx := context.Background()
	g, err := graphviz.New(ctx)
	if err != nil {
		return nil, err
	}
	defer g.Close()

	graph, err := graphviz.ParseBytes(raw)
	if err != nil {
		return nil, err
	}
	defer graph.Close()

	var buf bytes.Buffer
	if err := g.Render(ctx, graph, format, &buf); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func dotToPngBytes(raw []byte) ([]byte, error) {
	return render(raw, graphviz.PNG)
}

func dotToSvgBytes(raw []byte) ([]byte, error) {
	return render(raw, graphviz.SVG)
}

func dotToPng(raw []byte, file string) error {
	b, err := dotToPngBytes(raw)
	if err != nil {
		return err
	}
	return os.WriteFile(file, b, 0644)
}

func dotToSvg(raw []byte, file string) error {
	b, err := dotToSvgBytes(raw)
	if err != nil {
		return err
	}
	return os.WriteFile(file, b, 0644)
}
