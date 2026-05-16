## 0.2.5

### May 16, 2026

CHANGES:

* DFD's can now have multiple `flow` blocks in the same direction
* DFD Flow's now have an optional `protocol` attribute
* DFD rendering supports various rendering options, currently targeting the protocol rendering. By default, `protocol` will be appended to a flow's label. But can also be color-coded, none, or both.
* DFD rendering now supports outputting in mermaid and d2 text
* DFD rendering to DOT and SVG/PNG no longer depends on CGO

## 0.2.4

### Jan 11, 2026

CHANGES:

* Now with backend block and ref attributes

## 0.2.3

### Dec 24, 2025

CHANGES:

* Threats are validated to have unique names, not descriptions

## 0.2.2

### Dec 24, 2025

CHANGES:

* Minor tweak to MD output to use Threat name
* Introduced version bumping script

## 0.2.1

### Dec 24, 2025

CHANGES:

* Fixing a panic error

## 0.2.0

### Dec 23, 2025

CHANGES:

* Major version update to support the following:
    * Split DFD CGO requirements
    * Threats have names
    * Expanded controls are just `control`

## 0.1.16

### Dec 3, 2025

CHANGES:

* Minor tweaks to deprecate ioutil and suppress some excessive logging

## 0.1.15

### Oct 13, 2025

CHANGES:

* When generating a string version of the HCL, after processing, remove `control_imports`

## 0.1.14

### Oct 4, 2025

CHANGES:

* Updated spec to 0.1.14
* Added a CHANGELOG file
* Added a CONTRIBUTING file
