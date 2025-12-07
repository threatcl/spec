# Security Review: threatcl/spec Package

**Review Date:** December 7, 2025
**Reviewer:** Security Assessment
**Scope:** HCL parsing security for internet-facing SaaS API on GCP Cloud Run
**Package Version:** 0.1.16

---

## Executive Summary

This security review identifies **critical vulnerabilities** in the `threatcl/spec` package that make it **unsuitable for processing untrusted user input** in its current form. The package was designed for local CLI usage and lacks the defensive controls necessary for a multi-tenant SaaS environment.

**Risk Rating: CRITICAL**

The most severe issues involve:
1. Server-Side Request Forgery (SSRF) via the `go-getter` library
2. Arbitrary file read via path traversal
3. Resource exhaustion leading to Denial of Service

---

## Critical Vulnerabilities

### 1. SSRF via go-getter (CRITICAL)

**Location:** `parser_threatmodel.go:158-227` (`fetchRemoteTm` function)

**Description:**
The `imports` and `including` fields in HCL files are passed directly to `hashicorp/go-getter` without any URL validation. This allows attackers to make the server fetch arbitrary URLs, including internal network resources and cloud metadata endpoints.

**Vulnerable Code:**
```go
// parser_threatmodel.go:186-195
splitSource := strings.SplitN(source, "|", 2)

client := gg.Client{
    Src:  splitSource[0],  // USER CONTROLLED - NO VALIDATION
    Dst:  tmpDir,
    Pwd:  absPath,
    Mode: gg.ClientModeAny,
}

err = client.Get()
```

**Attack Vectors:**

1. **GCP Metadata Service Access** - Steal service account tokens:
```hcl
threatmodel "malicious" {
  author = "attacker"
  imports = ["http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/token?alt=json"]
}
```

2. **Internal Service Discovery**:
```hcl
threatmodel "malicious" {
  author = "attacker"
  imports = ["http://internal-api.default.svc.cluster.local:8080/admin"]
}
```

3. **AWS Metadata (if running on AWS)**:
```hcl
threatmodel "malicious" {
  author = "attacker"
  imports = ["http://169.254.169.254/latest/meta-data/iam/security-credentials/"]
}
```

4. **S3 Bucket Access** (go-getter supports S3):
```hcl
threatmodel "malicious" {
  author = "attacker"
  imports = ["s3::https://s3.amazonaws.com/internal-bucket/secrets.hcl"]
}
```

**Impact:**
- Theft of GCP service account credentials
- Access to internal services and APIs
- Cloud infrastructure compromise
- Data exfiltration from internal networks

**CVSS Score:** 9.8 (Critical)

---

### 2. Path Traversal / Arbitrary File Read (CRITICAL)

**Location:** `parser_threatmodel.go:214-219`

**Description:**
The `includePath` is constructed using user-controlled input from the pipe (`|`) syntax without path sanitization. Attackers can use `../` sequences to read arbitrary files.

**Vulnerable Code:**
```go
// parser_threatmodel.go:214-219
switch len(splitSource) {
case 1:
    includePath = fmt.Sprintf("%s/%s", tmpDir, filepath.Base(source))
case 2:
    includePath = fmt.Sprintf("%s/%s", tmpDir, splitSource[1])  // NO SANITIZATION
}
importDiag := returnParser.ParseHCLFile(includePath, false)
```

**Attack Vector:**
```hcl
threatmodel "malicious" {
  author = "attacker"
  imports = ["./valid-repo|../../../../../../etc/passwd"]
}
```

Or via the `including` field:
```hcl
threatmodel "malicious" {
  author = "attacker"
  including = "./valid-repo|../../../proc/self/environ"
}
```

**Impact:**
- Read sensitive system files (`/etc/passwd`, `/etc/shadow`)
- Access environment variables containing secrets (`/proc/self/environ`)
- Read application configuration and credentials
- Information disclosure

**CVSS Score:** 8.6 (High)

---

### 3. Resource Exhaustion / Denial of Service (HIGH)

**Location:** Multiple locations throughout `parser.go` and `parser_threatmodel.go`

**Description:**
No resource limits are enforced on:
- Input file size
- Number of imports (recursive fetching)
- Depth of nested structures
- Number of threatmodels, threats, controls, data flow elements
- Circular import detection

**Attack Vectors:**

1. **Large File Attack:**
```hcl
// Submit a multi-gigabyte HCL file
threatmodel "large" {
  author = "attacker"
  description = "[... 10GB of data ...]"
}
```

2. **Import Bomb (Recursive/Circular):**
```hcl
// file_a.hcl
threatmodel "a" {
  author = "attacker"
  imports = ["file_b.hcl"]
}

// file_b.hcl
threatmodel "b" {
  author = "attacker"
  imports = ["file_a.hcl"]
}
```

3. **Deep Nesting:**
```hcl
threatmodel "deep" {
  author = "attacker"
  data_flow_diagram_v2 "dfd" {
    trust_zone "zone1" {
      trust_zone "zone2" {
        // ... deeply nested structures
      }
    }
  }
}
```

**Impact:**
- Memory exhaustion causing OOM kills
- CPU exhaustion
- Disk exhaustion via temp files
- Service unavailability affecting all tenants

**CVSS Score:** 7.5 (High)

---

## High Severity Vulnerabilities

### 4. Temporary File Leak (HIGH)

**Location:** `parser_threatmodel.go:161-168`

**Description:**
Temporary directories created by `os.MkdirTemp` are never cleaned up. The `os.RemoveAll` call is missing after `fetchRemoteTm` completes.

**Vulnerable Code:**
```go
tmpDir, err := os.MkdirTemp("", "hcltm")
if err != nil {
    return nil, err
}
// NO defer os.RemoveAll(tmpDir) HERE!

tmpDir = fmt.Sprintf("%s/nest", tmpDir)
// ... rest of function
// tmpDir is NEVER cleaned up
```

**Impact:**
- Disk exhaustion over time
- Potential information disclosure if temp files persist
- Crash loops when disk fills

---

### 5. Arbitrary File Write (HIGH)

**Location:** `dfd.go:309, 347`

**Description:**
The `GenerateDfdPng` and `GenerateDfdSvg` functions accept a `filepath` parameter that is used directly in `os.WriteFile`. If this parameter is derived from user input, attackers could overwrite arbitrary files.

**Vulnerable Code:**
```go
// dfd.go:309
func dotToPng(raw []byte, file string) error {
    pngBytes, err := dotToPngBytes(raw)
    if err != nil {
        return err
    }
    return os.WriteFile(file, pngBytes, 0644)  // NO PATH VALIDATION
}
```

**Note:** This depends on how the consuming application uses these functions. If the filepath is server-controlled, this is not exploitable.

---

## Medium Severity Vulnerabilities

### 6. DOT/Graphviz Injection (MEDIUM)

**Location:** `dfd.go:66-118`, `dfd.go:120-287`

**Description:**
User-controlled names (process names, zone names, flow names) are passed directly to the graphviz library. Maliciously crafted names could potentially:
- Inject DOT language commands
- Exploit vulnerabilities in the graphviz parser
- Cause rendering issues or crashes

**Example Attack:**
```hcl
data_flow_diagram_v2 "dfd" {
  process "evil\"; label=\"pwned" {
  }
}
```

---

### 7. Template Injection Risk (MEDIUM)

**Location:** `render.go:34-62`

**Description:**
The `ParseTMTemplate` function creates a Go template from a string. If the template content is user-controlled (not just the data), this could lead to information disclosure.

**Note:** Current usage appears to use server-controlled templates, but this should be documented.

---

## Low Severity Issues

### 8. Information Disclosure via Error Messages

**Location:** Multiple locations

**Description:**
Detailed error messages may reveal internal paths, stack traces, or system information to attackers.

---

## Dependency Analysis

### Direct Dependencies with Security Implications

| Dependency | Version | Security Notes |
|------------|---------|----------------|
| `github.com/hashicorp/go-getter` | v1.8.2 | **HIGH RISK** - Supports many protocols (http, https, git, s3, gcs, file). Must be restricted. |
| `github.com/goccy/go-graphviz` | v0.1.3 | Medium risk - Parses DOT format, potential for parser bugs |
| `github.com/hashicorp/hcl/v2` | v2.24.0 | Low risk - Well-maintained by HashiCorp |

### Transitive Dependencies

The package pulls in AWS SDK, GCP SDK, and other cloud dependencies via `go-getter`. This increases attack surface and requires careful IAM configuration.

---

## Recommendations

### Immediate Actions (Must Fix Before Production)

1. **Disable Remote Imports Entirely**
   - For SaaS usage, do NOT allow `imports` or `including` fields
   - Strip these fields before processing OR reject files containing them

   ```go
   // Add validation before processing
   func validateNoRemoteImports(f *hcl.File) error {
       imports, _ := extractImports(f)
       if len(imports) > 0 {
           return fmt.Errorf("remote imports are not allowed")
       }
       return nil
   }
   ```

2. **Implement Input Size Limits**
   ```go
   const MaxFileSize = 1 * 1024 * 1024 // 1MB

   func (p *ThreatmodelParser) ParseHCLRawSafe(input []byte) error {
       if len(input) > MaxFileSize {
           return fmt.Errorf("file exceeds maximum size of %d bytes", MaxFileSize)
       }
       return p.ParseHCLRaw(input)
   }
   ```

3. **Implement Structural Limits**
   ```go
   const (
       MaxThreatmodels = 10
       MaxThreatsPerModel = 100
       MaxControlsPerThreat = 50
       MaxDFDElements = 200
   )
   ```

4. **Add Request Timeouts**
   - Wrap all parsing operations in context with timeout
   - Limit CPU time per request

### Short-Term Mitigations

5. **If Remote Imports Are Required:**
   - Implement strict URL allowlist
   - Block RFC 1918 addresses (10.x, 172.16-31.x, 192.168.x)
   - Block link-local addresses (169.254.x.x)
   - Block localhost
   - Only allow HTTPS with verified certificates
   - Implement request signing/authentication

6. **Fix Temp File Cleanup**
   ```go
   defer os.RemoveAll(tmpDir)
   ```

7. **Sanitize File Paths**
   ```go
   func sanitizePath(base, userPath string) (string, error) {
       cleaned := filepath.Clean(userPath)
       if strings.Contains(cleaned, "..") {
           return "", fmt.Errorf("path traversal detected")
       }
       full := filepath.Join(base, cleaned)
       if !strings.HasPrefix(full, base) {
           return "", fmt.Errorf("path escapes base directory")
       }
       return full, nil
   }
   ```

### Architecture Recommendations

8. **Process Isolation**
   - Run HCL parsing in isolated containers/sandboxes
   - Use gVisor or similar for additional isolation on Cloud Run
   - Implement per-tenant resource quotas

9. **Network Isolation**
   - Configure VPC to prevent access to metadata endpoints
   - Use Cloud Run's VPC egress settings to restrict outbound traffic
   - Block access to internal services from parsing containers

10. **Monitoring & Alerting**
    - Log all parsing operations with user context
    - Alert on unusual patterns (large files, many imports, errors)
    - Implement rate limiting per user/tenant

---

## Testing Checklist

Before deploying to production, verify:

- [ ] Remote imports (`imports`, `including`) are blocked or restricted
- [ ] File size limits are enforced
- [ ] Structural limits prevent resource exhaustion
- [ ] Path traversal attacks are blocked
- [ ] Cloud metadata endpoints are inaccessible
- [ ] Temp files are properly cleaned up
- [ ] Error messages don't leak sensitive information
- [ ] Request timeouts are configured
- [ ] Rate limiting is in place

---

## Conclusion

**Do not use this package to process untrusted user input without implementing the recommended mitigations.** The current design assumes trusted input from local file operations and is not suitable for a multi-tenant SaaS environment.

The most critical action is to **completely disable or heavily restrict the remote import functionality** (`imports` and `including` fields) as these expose severe SSRF and path traversal vulnerabilities.

If you need the import functionality, consider building a separate, hardened import service with strict URL allowlisting and running it in complete network isolation from your main application.
