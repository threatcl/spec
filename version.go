package spec

// Version is the current spec version.
// This can be overridden at build time using:
//
//	go build -ldflags "-X github.com/threatcl/spec.Version=x.y.z"
var Version = "0.2.4"

// OtmVersion is the Open Threat Model format version.
// This can be overridden at build time using:
//
//	go build -ldflags "-X github.com/threatcl/spec.OtmVersion=x.y.z"
var OtmVersion = "0.2.0"
