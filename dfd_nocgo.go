//go:build !cgo

package spec

import "errors"

var errNoCgo = errors.New("image rendering requires CGO; use GenerateDot() to get DOT output instead")

func dotToPngBytes(raw []byte) ([]byte, error) {
	return nil, errNoCgo
}

func dotToPng(raw []byte, file string) error {
	return errNoCgo
}

func dotToSvgBytes(raw []byte) ([]byte, error) {
	return nil, errNoCgo
}

func dotToSvg(raw []byte, file string) error {
	return errNoCgo
}
