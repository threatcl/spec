# SLSA posture & roadmap

This document tracks the [SLSA](https://slsa.dev) (Supply-chain Levels for
Software Artifacts) posture of `github.com/threatcl/spec`. It states where we
are today, where we're going, and maps every planned change to a specific SLSA
**track** and **level**.

> **Status:** All three phases complete. Phase 2 rulesets are active on the repo
> (commit + tag signing in force); the first attested release is produced when
> the next `vX.Y.Z` tag is pushed (see [Verification](#verification)).

## What this repo is (and why it matters for SLSA)

`threatcl/spec` is a **pure Go library** (`package spec`). It ships **no binary
of its own** — the only `main` package is `scripts/bump_version.go`, a local dev
helper. Downstream consumers (notably the `threatcl` CLI) pull it via `go get` /
the Go module proxy.

This shapes which SLSA track is worth investing in:

- The **Build track** (build → artifact provenance) only becomes meaningful once
  we publish an *artifact to attest*. A library consumed as source has nothing
  to attest until we deliberately produce a release artifact (Phase 3). We
  should not oversell Build provenance for a repo that currently ships no
  binaries.
- The **Source track** (protected, attestable source revisions) is the
  higher-leverage target: it protects the revisions that downstreams actually
  consume.

The end users' verifiable supply chain ultimately lives in the **downstream
`threatcl` CLI**, which compiles and ships binaries. Wiring Build L3 provenance
there is the single highest-impact follow-up (see [Highest-impact next
step](#highest-impact-next-step)). This repo's job is to be a hardened,
attestable *source*.

## Reference: SLSA levels

**Build track** — [slsa.dev/spec/v1.1/levels](https://slsa.dev/spec/v1.1/levels):

| Level | Name | Requires |
|-------|------|----------|
| L0 | (none) | No guarantees. |
| L1 | Provenance exists | Consistent build process; platform auto-generates provenance (may be unsigned). |
| L2 | Hosted build platform | Build runs on a hosted platform that **generates and signs** provenance; consumers validate it. |
| L3 | Hardened builds | L2 + build runs are isolated from each other and signing secrets are unreachable from user build steps (non-forgeable provenance). |

**Source track** — [slsa.dev/spec/v1.2/source-requirements](https://slsa.dev/spec/v1.2/source-requirements):

| Level | Name | Requires (cumulative) |
|-------|------|-----------------------|
| L1 | Version Controlled | VCS with uniquely identifiable repo + revision IDs; human-readable diffs; authenticated actor identities; a Source **VSA** is generated. |
| L2 | History & Provenance | Branch history continuous, immutable, retained; **force-push prevented**; access controls on sensitive ops; tag immutability; SCS issues Source Provenance Attestations per revision. |
| L3 | Continuous Technical Controls | Platform continuously enforces the org's technical controls on named/protected references and records them in contemporaneous attestations. |
| L4 | Two-Party Review | All changes to protected branches reviewed by **two trusted persons** (distinct uploader/reviewer); security-relevant review; re-review on post-review changes. |

## Current state (baseline)

| Track | Level today | Evidence |
|-------|-------------|----------|
| **Build** | **L0** | No artifact is produced and no provenance is generated. `gh release list` is empty; releases are git tags only. |
| **Source** | **~L1 in substance, not formally** | git + GitHub provide identifiable revisions, readable diffs, and authenticated identities (the *substance* of L1), **but** no Source VSA is emitted and `main` has **no branch protection** — so neither formal L1 (VSA) nor L2 (immutable-history controls) is satisfied. |

Detailed findings from recon:

- **CI:** one workflow, `.github/workflows/testvet.yml` (`make vet` + `make test`
  on `[push, pull_request]`). Actions float on major tags
  (`actions/checkout@v4`, `actions/setup-go@v4`). **No top-level `permissions:`**
  block, so the default (often broad) token scope applies.
- **Releases:** annotated git tags only (`v0.3.1`, `v0.3.0`, …). No GitHub
  Releases, no artifacts, no `SHA256SUMS`, no provenance, no signing tooling.
- **Signing:** PR merge commits are GPG-signed by GitHub (`web-flow`,
  `verified: true`). Direct local commits and **release tags are unsigned**.
- **Dependencies:** no Dependabot / no automated update or pinning policy.
- **No** `CODEOWNERS`, `SECURITY.md`, or branch-protection ruleset in the repo.
- **Note (non-SLSA, but relevant to Phase 3 determinism):** CI pins
  `go-version: '1.22'` while `go.mod` declares `go 1.24.6`. CI silently
  auto-downloads the 1.24 toolchain. We should pin one Go version explicitly
  before relying on reproducible release artifacts.

## Roadmap

Each phase is gated on maintainer review. The table maps changes to the SLSA
track/level they advance. **Hygiene items (Phase 1) do not move a SLSA *level*
by themselves** — they harden the platform and are prerequisites that make the
Source and Build tracks trustworthy (and improve OpenSSF Scorecard).

| Phase | Change | Track → Level it advances |
|-------|--------|---------------------------|
| **1** | Pin all Actions to full commit SHAs (`# vX.Y.Z` comment) | Hygiene — reduces build-platform tamper surface (supports Build L2+/Source L3 trust) |
| **1** | `dependabot.yml` for `github-actions` + `gomod` | Hygiene — keeps pins current & auditable |
| **1** | Least-privilege `permissions: contents: read` on `testvet.yml` | Hygiene — least privilege on the CI token |
| **2** | Branch-protection ruleset on `main` (require PR review + `testvet` check, block force-push, restrict deletion, linear history) | **Source L2 → L3** technical controls |
| **2** | Require **signed commits** | Source L1 identity / L2 provenance strengthening |
| **2** | **Signed release tags** workflow | Source authenticity of release points |
| **2** | `CODEOWNERS` (committed file) | Supports review routing toward Source L4 |
| **3** | Tag-triggered release workflow: source archive + `SHA256SUMS` + GitHub Release | Produces the artifact that makes the **Build track** meaningful (Build L1) |
| **3** | `actions/attest-build-provenance` on release artifacts | **Build L2**, positioned as **L3-equivalent** (see caveat below) |

### Caveat on "Build L3" via native GitHub attestations

`actions/attest-build-provenance` generates Sigstore-signed SLSA provenance from
a GitHub-hosted runner. Out of the box this cleanly meets **Build L2** (hosted
platform generates + signs provenance). GitHub positions it as reaching **L3**
because the attestation is minted by GitHub's trusted control plane (OIDC →
Fulcio), not by user-controllable build steps. We'll describe Phase 3 as
**"Build L2, L3-equivalent provenance"** rather than asserting a bare "L3" —
honest, and still a real tag → artifact verifiable link.

Also note the artifact in Phase 3 is a **repackaging of source** (archive +
checksums), not a compiled binary. The provenance is genuine but its value is
bounded — the high-value compiled-binary provenance belongs downstream in the
`threatcl` CLI.

## Progress tracker

- [x] **Phase 0** — Recon, baseline assessment, this document.
- [x] **Phase 1** — Supply-chain hygiene: SHA-pinned actions in `testvet.yml`,
  `.github/dependabot.yml` (`github-actions` + `gomod`), least-privilege
  `permissions: contents: read`.
- [x] **Phase 2 (committed artifacts)** — `.github/CODEOWNERS`, importable
  branch + tag rulesets under `.github/rulesets/`, and signed-tag guidance in
  `CONTRIBUTING.md`. **Activation is a maintainer action** — see checklist.
- [x] **Phase 3** — Releases + Build provenance: `.github/workflows/release.yml`
  (tag-triggered → deterministic source archive + `SHA256SUMS` + GitHub Release
  + Sigstore-signed SLSA provenance via `actions/attest-build-provenance`), a
  `make version` target reused by the release guard, `testvet` Go version sourced
  from `go.mod` (also bumped CI actions to `checkout` v7 / `setup-go` v6 —
  required because setup-go v6 enforces `GOTOOLCHAIN=local`, which surfaced the
  Phase 0 Go-version mismatch), and the [Verification](#verification) section.

## Maintainer checklist — GitHub settings (Phase 2)

Phase 2 ships three **committed** artifacts:

- `.github/CODEOWNERS` — default owner `@xntrik`.
- `.github/rulesets/main-protection.json` — importable branch ruleset for `main`.
- `.github/rulesets/tag-protection.json` — importable tag ruleset for `v*` tags.

Plus signed-tag guidance in [`CONTRIBUTING.md`](../CONTRIBUTING.md). The rulesets
are **not auto-applied** — GitHub never reads these files. They are
version-controlled templates you import by hand. Do the steps below in order.

### Step 1 — Set up signing (do this first)

Both rulesets require signatures. Configure SSH-based signing (no GPG needed —
GPG isn't even installed locally):

```
git config --global gpg.format ssh
git config --global user.signingkey ~/.ssh/id_ed25519.pub
git config --global commit.gpgsign true
git config --global tag.gpgsign true
```

Then add that key to GitHub as a **Signing Key** (Settings → SSH and GPG keys →
New SSH key → type "Signing key"). Verify with `git log --show-signature` /
`git tag -v vX.Y.Z`.

- [x] SSH signing configured locally and signing key added to GitHub.

> **Sign *before* you open PRs.** The signature rule is enforced at the PR merge
> gate: GitHub blocks the merge while **any commit in the PR is unverified**,
> *even for squash merges*. (GitHub's `web-flow` key signs the *resulting* squash
> commit, but that doesn't excuse an unsigned commit on the head branch.) If a
> branch already has unsigned commits, re-sign them and force-push before
> merging:
> ```
> git rebase -f -S main && git push --force-with-lease
> ```
> **Tags** are created and pushed locally — GitHub can't sign them for you — so
> `git tag -s` is mandatory once the tag ruleset is active.
>
> *Agent-backed keys (Secretive/Secure Enclave, 1Password, YubiKey):* set
> `user.signingkey` to the literal key (`key::ssh-ed25519 AAAA…`) instead of a
> file path, and make sure `SSH_AUTH_SOCK` points at that agent — git's signer
> finds the agent via `SSH_AUTH_SOCK`, not via `IdentityAgent` in `ssh_config`.

### Step 2 — Import the `main` branch ruleset

Settings → Rules → Rulesets → **New ruleset → Import a ruleset** → select
`.github/rulesets/main-protection.json`. It encodes:

- [ ] Require a pull request before merging (**0 approvals** — solo-maintainer
  default; see note).
- [ ] Require status check **`testvet`** to pass (strict / up-to-date).
- [ ] **Block force-pushes** (`non_fast_forward`) — Source L2 move-forward-only.
- [ ] **Restrict deletions** of `main`.
- [ ] **Require linear history** + **squash-only** merges.
- [ ] **Require signed commits** (`required_signatures`).

> **Solo-maintainer config (shipped default):** the committed JSON sets
> `required_approving_review_count: 0` and `require_code_owner_review: false`.
> This still **requires every change to go through a PR** and still enforces the
> `testvet` check, signatures, no-force-push, and linear history *on you* — you
> just don't need an approval you can't give yourself. `bypass_actors: []`
> stays empty, so none of those gates are skippable.
>
> **When you add a second reviewer**, bump `required_approving_review_count` to
> `1` and set `require_code_owner_review: true` — that reaches true Source L4
> two-party review, and `CODEOWNERS` is already in place to route it.
>
> **Avoid the bypass route for this.** A bypass actor skips the *entire* ruleset
> (CI gate, signatures, force-push protection — not just review), so it's a much
> bigger hole than 0-approval PRs. If you ever do need one (e.g. an automated
> release bot): ruleset → **Bypass list → Add bypass** → pick *Repository admin*
> or *Organization admin* → mode *Always* or *For pull requests only*. In JSON
> that's `"bypass_actors": [{ "actor_id": 5, "actor_type": "RepositoryRole",
> "bypass_mode": "always" }]` (5 = built-in Admin role; org-admin is
> `"actor_type": "OrganizationAdmin", "actor_id": 1`). Surest way to get the
> exact IDs: set it in the UI, then re-export the ruleset to JSON.
>
> **Workflow change:** linear history + squash-only means no more merge commits;
> PRs merge as a single squashed (GitHub-signed) commit.

### Step 3 — Import the tag ruleset

Same flow, importing `.github/rulesets/tag-protection.json`. It makes `v*` tags
**immutable and signed**:

- [ ] Block tag **deletion** and **update/force** (`deletion`, `update`,
  `non_fast_forward`) — Source L2 tag immutability.
- [ ] **Require signed tags** (`required_signatures`). Existing unsigned tags are
  unaffected; this applies to new tags only. Don't activate this before Step 1
  or your next `git push --tags` will be rejected.

### What this advances

Activating both rulesets moves the **Source track** from "L1 in substance" to
the **L2/L3 technical-control** posture: continuous, enforced controls on a named
reference (`main`) and on release tags — immutable history, blocked force-push,
required signatures, required status check. **Source L4** (two-party review)
remains gated on a second reviewer. Note the formal **Source VSA** that the spec
expects an SCS to emit is still not produced (GitHub doesn't emit one yet) — so
this is "L2/L3 controls in force," not a platform-attested L2/L3.

## Verification

Pushing a tag `vX.Y.Z` runs `.github/workflows/release.yml`, which publishes a
GitHub Release with these assets:

- `spec-X.Y.Z.tar.gz` — a **deterministic** source archive (`git archive` with
  fixed mtimes, piped through `gzip -n`).
- `SHA256SUMS` — its SHA-256 checksum.
- A Sigstore-signed **SLSA build provenance** attestation (generated by
  `actions/attest-build-provenance`, stored in the repo's attestation store).

To verify a downloaded release (needs `gh` ≥ 2.49 and network):

```bash
# 1. Integrity — the archive matches the published checksum:
sha256sum -c SHA256SUMS

# 2. Provenance — the archive was built by THIS repo's release workflow,
#    on a GitHub-hosted runner, from the tagged commit:
gh attestation verify spec-X.Y.Z.tar.gz --repo threatcl/spec
gh attestation verify SHA256SUMS        --repo threatcl/spec
```

`gh attestation verify` matches the artifact's digest against the signed
provenance and confirms the build came from `.github/workflows/release.yml` in
`threatcl/spec`. **Verify the `spec-X.Y.Z.tar.gz` asset**, not GitHub's
auto-generated "Source code (zip/tar.gz)" links — those are unattested and not
byte-reproducible.

### What Phase 3 advances

This takes the **Build track** from L0 to **L2, positioned as L3-equivalent**:
the provenance is generated and Sigstore-signed by GitHub's hosted control plane
(OIDC → Fulcio), unreachable from user build steps. Caveat (unchanged): the
artifact is a *source repackaging*, not a compiled binary, so the provenance is
genuine but bounded in value — the high-leverage target remains compiled-binary
provenance in the downstream `threatcl` CLI (see below). A failed
tag-vs-`version.go` check stops a mistagged release before it publishes.

## Highest-impact next step

The most valuable supply-chain win is **not** in this library — it's wiring
**Build L3 provenance into the downstream `threatcl` CLI**, which actually
compiles and ships binaries to end users. Attesting those binaries gives users a
verifiable chain from source → released executable. This repo's hardening
(Source track + a release-artifact provenance pattern) is the groundwork; the
payoff is replicating the Phase 3 pattern there against real compiled artifacts.
Tracked here as a flag only — not implemented in this repo.
