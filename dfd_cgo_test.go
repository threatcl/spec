//go:build cgo

package spec

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"strings"
	"testing"
)

func TestDfdPngGenerate(t *testing.T) {
	// tm := dfdTm()
	//
	// fulltm := fullDfdTm()

	cases := []struct {
		name        string
		tm          *Threatmodel
		exp         string
		errorthrown bool
	}{
		{
			"valid_dfd",
			dfdTm(),
			"",
			false,
		},
		{
			"valid_full_dfd",
			fullDfdTm(),
			"",
			false,
		},
		{
			"valid_full_dfd2",
			fullDfdTm2(),
			"",
			false,
		},
	}

	for _, tc := range cases {
		tc := tc

		t.Run(tc.name, func(t *testing.T) {
			// t.Parallel()

			d, err := ioutil.TempDir("", "")
			if err != nil {
				t.Fatalf("Error creating tmp dir: %s", err)
			}
			defer os.RemoveAll(d)

			for _, adfd := range tc.tm.DataFlowDiagrams {
				err = adfd.GenerateDfdPng(fmt.Sprintf("%s/out.png", d), tc.tm.Name)
			}

			if err != nil {
				if !strings.Contains(err.Error(), tc.exp) {
					t.Errorf("%s: Error rendering png: %s", tc.name, err)
				}
			} else {
				if tc.errorthrown {
					t.Errorf("%s: an error was thrown when it shoulnd't have", tc.name)
				} else {

					// at this point we should have a legitimate png to
					// test

					f, err := os.Open(fmt.Sprintf("%s/out.png", d))
					if err != nil {
						t.Fatalf("%s: Error opening png: %s", tc.name, err)
					}

					buffer := make([]byte, 512)
					_, err = f.Read(buffer)
					if err != nil {
						t.Fatalf("%s: Error reading png: %s", tc.name, err)
					}

					if http.DetectContentType(buffer) != "image/png" {
						t.Errorf("%s: The output file isn't a png, it's '%s'", tc.name, http.DetectContentType(buffer))
					}
				}
			}

		})
	}
}

func TestDfdSvgGenerate(t *testing.T) {
	cases := []struct {
		name        string
		tm          *Threatmodel
		exp         string
		errorthrown bool
	}{
		{
			"valid_dfd",
			dfdTm(),
			"",
			false,
		},
		{
			"valid_full_dfd",
			fullDfdTm(),
			"",
			false,
		},
		{
			"valid_full_dfd2",
			fullDfdTm2(),
			"",
			false,
		},
	}

	for _, tc := range cases {
		tc := tc

		t.Run(tc.name, func(t *testing.T) {
			// t.Parallel()

			d, err := ioutil.TempDir("", "")
			if err != nil {
				t.Fatalf("Error creating tmp dir: %s", err)
			}
			defer os.RemoveAll(d)

			for _, adfd := range tc.tm.DataFlowDiagrams {
				err = adfd.GenerateDfdSvg(fmt.Sprintf("%s/out.svg", d), tc.tm.Name)
			}

			if err != nil {
				if !strings.Contains(err.Error(), tc.exp) {
					t.Errorf("%s: Error rendering svg: %s", tc.name, err)
				}
			} else {
				if tc.errorthrown {
					t.Errorf("%s: an error was thrown when it shouldn't have", tc.name)
				} else {

					// at this point we should have a legitimate svg to
					// test

					f, err := os.Open(fmt.Sprintf("%s/out.svg", d))
					if err != nil {
						t.Fatalf("%s: Error opening svg: %s", tc.name, err)
					}

					buffer := make([]byte, 512)
					_, err = f.Read(buffer)
					if err != nil {
						t.Fatalf("%s: Error reading svg: %s", tc.name, err)
					}

					contentType := http.DetectContentType(buffer)
					if !strings.Contains(contentType, "xml") && !strings.Contains(contentType, "svg") {
						t.Errorf("%s: The output file isn't a svg, it's '%s'", tc.name, contentType)
					}
				}
			}

		})
	}
}

func TestDfdPngGenerateBytes(t *testing.T) {
	cases := []struct {
		name        string
		tm          *Threatmodel
		exp         string
		errorthrown bool
	}{
		{
			"valid_dfd",
			dfdTm(),
			"",
			false,
		},
		{
			"valid_full_dfd",
			fullDfdTm(),
			"",
			false,
		},
		{
			"valid_full_dfd2",
			fullDfdTm2(),
			"",
			false,
		},
	}

	for _, tc := range cases {
		tc := tc

		t.Run(tc.name, func(t *testing.T) {
			// t.Parallel()

			for _, adfd := range tc.tm.DataFlowDiagrams {
				pngBytes, err := adfd.GenerateDfdPngBytes(tc.tm.Name)

				if err != nil {
					if !strings.Contains(err.Error(), tc.exp) {
						t.Errorf("%s: Error generating png bytes: %s", tc.name, err)
					}
				} else {
					if tc.errorthrown {
						t.Errorf("%s: an error was thrown when it shouldn't have", tc.name)
					} else {
						// Verify the bytes are actually a PNG
						if http.DetectContentType(pngBytes) != "image/png" {
							t.Errorf("%s: The output bytes aren't a png, they're '%s'", tc.name, http.DetectContentType(pngBytes))
						}
					}
				}
			}
		})
	}
}

func TestDfdSvgGenerateBytes(t *testing.T) {
	cases := []struct {
		name        string
		tm          *Threatmodel
		exp         string
		errorthrown bool
	}{
		{
			"valid_dfd",
			dfdTm(),
			"",
			false,
		},
		{
			"valid_full_dfd",
			fullDfdTm(),
			"",
			false,
		},
		{
			"valid_full_dfd2",
			fullDfdTm2(),
			"",
			false,
		},
	}

	for _, tc := range cases {
		tc := tc

		t.Run(tc.name, func(t *testing.T) {
			// t.Parallel()

			for _, adfd := range tc.tm.DataFlowDiagrams {
				tmpFile, err := ioutil.TempFile("", "dfd")
				if err != nil {
					t.Fatalf("Error creating tmp file: %s", err)
				}
				defer os.RemoveAll(tmpFile.Name())

				dot, err := adfd.generateDfdDotFile(tmpFile.Name(), tc.tm.Name)
				if err != nil {
					t.Fatalf("Error generating dot: %s", err)
				}

				svgBytes, err := dotToSvgBytes([]byte(dot))
				if err != nil {
					if !strings.Contains(err.Error(), tc.exp) {
						t.Errorf("%s: Error generating svg bytes: %s", tc.name, err)
					}
				} else {
					if tc.errorthrown {
						t.Errorf("%s: an error was thrown when it shouldn't have", tc.name)
					} else {
						contentType := http.DetectContentType(svgBytes)
						if !strings.Contains(contentType, "xml") && !strings.Contains(contentType, "svg") {
							t.Errorf("%s: The output bytes aren't a svg, they're '%s'", tc.name, contentType)
						}
					}
				}
			}
		})
	}
}
