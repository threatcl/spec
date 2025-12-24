# Version Management

This project uses a centralized version management system to make version bumps easier and more consistent.

## How It Works

All version information is stored in `version.go`:

```go
var Version = "0.2.1"      // Spec version
var OtmVersion = "0.2.0"   // OTM format version
```

These variables are:
- Used throughout the codebase (config.go, render_otm.go, tests)
- Can be overridden at build time using `-ldflags`
- Automatically referenced in test files

## Bumping Versions

### Quick Method (Recommended)

Use the Makefile target to bump versions:

```bash
make bump-version OLD=0.2.1 NEW=0.2.2
```

This will:
1. Update `version.go` with the new version
2. Update all test data files (.hcl and .json) in the testdata directory
3. Show you next steps

### Manual Method

If you prefer to do it manually:

1. Edit `version.go` and change the Version variable
2. Run tests to ensure everything still works: `make test`
3. Update CHANGELOG.md manually
4. Commit your changes

### Dry Run

To see what files would be changed without making changes:

```bash
go run scripts/bump_version.go -old 0.2.1 -new 0.2.2 -dry-run
```

## Building with Custom Version

You can override the version at build time:

```bash
# Using make
make build VERSION=1.0.0

# Using go directly
go build -ldflags "-X github.com/threatcl/spec.Version=1.0.0"
```

This is useful for:
- CI/CD pipelines that want to use git tags as version
- Building releases with specific version numbers
- Development builds

## Version Variables

- **Version**: The spec version used for threatmodel files
- **OtmVersion**: The Open Threat Model format version (can be different from spec version)

## What Gets Updated

When you bump versions, the following are automatically updated:

1. `version.go` - The source of truth
2. All `.hcl` files in `testdata/` and subdirectories
3. All `.json` files in `testdata/` and subdirectories

You still need to manually update:
- `CHANGELOG.md` - Add release notes
- Any hardcoded version strings outside of testdata (rare)

## Best Practices

1. **Always run tests** after bumping versions: `make test`
2. **Update CHANGELOG.md** with release notes
3. **Use semantic versioning** (MAJOR.MINOR.PATCH)
4. **Keep OtmVersion in sync** with Version unless there's a specific reason not to
5. **Review the diff** before committing: `git diff`

## Example Workflow

```bash
# 1. Bump the version
make bump-version OLD=0.2.1 NEW=0.2.2

# 2. Update CHANGELOG.md
vim CHANGELOG.md

# 3. Run tests
make test

# 4. Review changes
git diff

# 5. Commit
git add .
git commit -m "chore: bump version to 0.2.2"

# 6. Tag (optional)
git tag v0.2.2
```
