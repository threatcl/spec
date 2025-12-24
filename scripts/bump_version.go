package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

func main() {
	var newVersion string
	var oldVersion string
	var dryRun bool

	flag.StringVar(&newVersion, "new", "", "New version (e.g., 0.2.2)")
	flag.StringVar(&oldVersion, "old", "", "Old version to replace (e.g., 0.2.1)")
	flag.BoolVar(&dryRun, "dry-run", false, "Show what would be changed without making changes")
	flag.Parse()

	if newVersion == "" {
		fmt.Println("Usage: go run scripts/bump_version.go -old <old_version> -new <new_version> [-dry-run]")
		fmt.Println("Example: go run scripts/bump_version.go -old 0.2.1 -new 0.2.2")
		os.Exit(1)
	}

	if oldVersion == "" {
		fmt.Println("Error: -old flag is required")
		fmt.Println("Example: go run scripts/bump_version.go -old 0.2.1 -new 0.2.2")
		os.Exit(1)
	}

	// Files to update
	filesToUpdate := []string{
		"version.go",
	}

	// Find all test data files
	testDataFiles := []string{}
	err := filepath.Walk("testdata", func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() && (strings.HasSuffix(path, ".hcl") || strings.HasSuffix(path, ".json")) {
			testDataFiles = append(testDataFiles, path)
		}
		return nil
	})

	if err != nil {
		fmt.Printf("Warning: Could not walk testdata directory: %v\n", err)
	}

	allFiles := append(filesToUpdate, testDataFiles...)

	if dryRun {
		fmt.Printf("DRY RUN: Would update version from %s to %s in the following files:\n", oldVersion, newVersion)
		for _, file := range allFiles {
			fmt.Printf("  - %s\n", file)
		}
		return
	}

	// Update version.go
	if err := updateVersionFile("version.go", oldVersion, newVersion); err != nil {
		fmt.Printf("Error updating version.go: %v\n", err)
		os.Exit(1)
	}

	// Update test data files
	updated := 0
	for _, file := range testDataFiles {
		if err := updateTestDataFile(file, oldVersion, newVersion); err != nil {
			fmt.Printf("Warning: Could not update %s: %v\n", file, err)
		} else {
			updated++
		}
	}

	fmt.Printf("✓ Version bumped from %s to %s\n", oldVersion, newVersion)
	fmt.Printf("✓ Updated version.go\n")
	fmt.Printf("✓ Updated %d test data files\n", updated)
	fmt.Printf("\nNext steps:\n")
	fmt.Printf("  1. Review changes: git diff\n")
	fmt.Printf("  2. Update CHANGELOG.md manually\n")
	fmt.Printf("  3. Run tests: make test\n")
	fmt.Printf("  4. Commit: git commit -m 'chore: bump version to %s'\n", newVersion)
}

func updateVersionFile(filename, oldVersion, newVersion string) error {
	content, err := os.ReadFile(filename)
	if err != nil {
		return err
	}

	// Update the Version variable
	versionRegex := regexp.MustCompile(`var Version = "` + regexp.QuoteMeta(oldVersion) + `"`)
	newContent := versionRegex.ReplaceAllString(string(content), `var Version = "`+newVersion+`"`)

	if newContent == string(content) {
		return fmt.Errorf("no changes made - version %s not found", oldVersion)
	}

	return os.WriteFile(filename, []byte(newContent), 0644)
}

func updateTestDataFile(filename, oldVersion, newVersion string) error {
	content, err := os.ReadFile(filename)
	if err != nil {
		return err
	}

	// Replace spec_version strings in both HCL and JSON formats
	oldContent := string(content)
	newContent := strings.ReplaceAll(oldContent, `"`+oldVersion+`"`, `"`+newVersion+`"`)

	// Only write if there were changes
	if newContent == oldContent {
		return nil // No changes needed
	}

	return os.WriteFile(filename, []byte(newContent), 0644)
}
