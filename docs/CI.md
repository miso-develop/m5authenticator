# CI and deployment routing

This document describes the repository-owned CI impact model used by GitHub Actions.

## Required security invariant

The protected `main` branch requires the GitHub Actions check context:

`security:scan`

`.github/workflows/security.yml` runs for every pull request and every push to `main`. It has no path filter and the `security:scan` job is not conditionally skipped. The workflow keeps the full security, release authorization, attestation, supply-chain, and repository-security contract suite.

The required security check also runs the CI-routing regression tests so a routing change cannot silently remove this invariant.

## Change-impact categories

`scripts/ci_change_impact.py` is the canonical classifier. It emits:

- `web`
- `firmware`
- `pages`
- `security_release_shared`
- `snapshot_contract`
- `snapshot_build`
- `process_docs_only`
- `uncertain`

The classifier consumes the complete Git changed-path set.

For pull requests it uses the pull request base SHA through head SHA. For pushes to `main` it uses the event `before` through `after` SHA. Renames include both the old and new paths, and deletes are included.

### Fail-safe behavior

Unknown or unclassified paths are treated as shared impact and run the normal heavy Web and Firmware validation.

The classifier also fails safe when it cannot establish a trustworthy diff, including:

- missing or unavailable base/head commits;
- an all-zero push base;
- malformed event SHAs;
- insufficient checkout history;
- Git diff failure;
- an empty/indeterminate changed-path set.

In those cases `uncertain=true` and all heavy categories are enabled. CI uncertainty must increase validation, never skip it.

## Foundation routing

`.github/workflows/foundation.yml` still starts on every pull request and every push to `main`.

Its lightweight `classify` job always runs and performs the complete-history diff. Heavy jobs are conditional only after classification:

| Impact | Linux Web | Windows Chrome QR/Argon2 | Firmware |
| --- | --- | --- | --- |
| Process/docs only | skip | skip | skip |
| Web | run | run | skip |
| Firmware | skip | skip | run |
| Shared/unknown | run | run | run |

Changes to Foundation/Security/Pages/release workflow routing, release/package/supply-chain inputs, or the classifier itself are Shared and therefore exercise all heavy jobs.

## Local production-equivalent Web smoke

Web and Shared changes run a production-equivalent browser smoke in Foundation without requiring an ESP-IDF build.

The smoke:

- performs a real Vite production build with base `/m5authenticator/`;
- keeps the real Provisioner, Firmware Flash, and Help HTML/CSP;
- enables the normal Firmware Flash surface;
- emits only synthetic, non-secret firmware manifests and tiny fixture binaries into the dedicated `production-smoke` output;
- serves that output from a local static Vite preview server;
- loads the real Provisioner, Firmware Flash, and Help routes in Chrome;
- verifies the Firmware page can load and validate the same-origin target/manifests;
- fetches every synthetic firmware part same-origin.

The synthetic fixture plugin is enabled only for test build modes. A normal production Pages build does not emit those fixture assets.

The existing QR and Argon2 production-bundle coverage remains independent and still runs for Web/Shared changes.

## Pages cadence

`.github/workflows/pages.yml` does not deploy on ordinary `main` pushes.

Automatic production deployment occurs only for protected SemVer tag pushes matching `v*.*.*`.

A manual `workflow_dispatch` path exists only for the explicit pre-release candidate gate. It requires:

- invocation from `refs/heads/main`;
- explicit candidate acknowledgement;
- an exact 40-character `candidate_sha`;
- freshly fetched `origin/main` equal to the workflow source SHA;
- `candidate_sha` equal to that same current-main SHA.

A candidate run writes the exact source/build identity to the run summary and forces `exact_release=false`. A manual candidate is a mutable public Pages deployment, not an immutable GitHub Release.

Tag and manual candidate runs preserve the production build/deployment path:

- release-profile validation;
- immutable ESP-IDF image identity;
- isolated firmware build;
- firmware image/package validation;
- same-origin firmware assets;
- production Web build;
- one Pages staging artifact with one-day retention;
- exact artifact-ID deletion after deployment.

Because the manual candidate overwrites the public Pages site, it is used only when an approved release gate explicitly calls for hosted production validation.

## Web-only Pages with immutable released firmware

`.github/workflows/pages-web-released-firmware.yml` is a separate manual-only production path for post-release Web/static publication. It does not change the existing SemVer-tag Pages path or the pre-release candidate path in `pages.yml`.

The operator must provide:

- an exact `web_sha` that still equals freshly fetched protected `main`;
- an existing canonical SemVer `firmware_release_tag`;
- the explicit deployment acknowledgement.

The unprivileged build/verify job fails closed unless current-main required checks pass using the same repository-owned semantics as Authorized Release. It derives firmware source identity from the selected tag, requires an immutable non-draft/non-prerelease GitHub Release, validates the active SemVer tag-immutability Ruleset, requires the release source to be an ancestor of the selected Web SHA, and requires current/release `firmware/release-profile.json` to match exactly except for `firmware_version`.

Historical Release source is treated as data only. Current-main `scripts/ci_pages_released_firmware.py` reads exactly the Specification-approved fixed Git-blob allowlist from the peeled source SHA, requires ordinary non-executable `100644` blobs, materializes only those bytes into an isolated temporary validation-data directory outside the workspace, and applies current-main `validate_release` logic with explicit paths. No historical script/module/worktree is executed or added to `PATH`/`PYTHONPATH`. The temporary data tree is removed immediately after validation; later package/provenance stages consume only the bounded current-main-produced `released-firmware-source-validation.json` result.

Firmware is never rebuilt in this mode. Every existing Release asset is downloaded and verified against:

- GitHub Release API size and SHA-256 digest metadata;
- exact `SHA256SUMS` coverage and bytes;
- release metadata, firmware target, pinned manifests, and referenced binaries;
- standard GitHub Artifact Attestation provenance;
- the M5Authenticator custom signed release-provenance predicate.

The custom predicate intentionally allows the truthful recovery case where firmware `source_commit` differs from the publisher `workflow_sha`; both identities remain independently verified.

The Web build always uses the exact current-main SHA with `VITE_M5AUTH_WEB_EXACT_RELEASE=false`. Verified released firmware files remain unchanged and are copied into `web/dist/firmware/` only after the Vite build. The current-main canonical product `THIRD_PARTY_NOTICES.md` is independently verified and copied to the site root, so it is not falsely represented as an asset that existed in an older immutable Release.

One Pages staging artifact is uploaded with one-day retention. Only the deploy job receives `pages: write`, `id-token: write`, and `actions: write`; it deploys the preassembled artifact and deletes it afterward by exact artifact ID. The build/verify job has read-only contents/checks/statuses/attestations access and no Release/tag mutation authority.

This workflow shares the repository-wide `github-pages` concurrency group but uses `cancel-in-progress: false`, so a manually started Web-only deployment cannot cancel an in-progress release-stage deployment.

Merging this workflow does **not** authorize its first public use. The first activation remains blocked until Issue #227's public third-party-notice remediation and final `V1_0_1_REMEDIATION` disposition are complete, followed by the exact-SHA/tag Human Gate recorded for Issue #229. If #227 concludes that v1.0.1 remediation is required, v1.0.0 is not an allowed firmware selection for that first activation.

## Screen snapshot diagnostics

The Issue117 workflow separates lightweight contract validation from diagnostics firmware build work.

Changes to snapshot procedure documentation, `AGENTS.md`, Windows diagnostic scripts, the host diagnostics helper, or snapshot contract tests run the lightweight snapshot contract job only.

The ESP-IDF diagnostics build runs only for true diagnostics firmware/build dependencies such as the relevant firmware profile, CMake/sdkconfig/device/time/session/vault-runtime inputs, ESP-IDF image pinning, or the snapshot workflow build semantics.

Docs-only or AGENTS-only changes therefore do not build diagnostics firmware.

## Authorized Release artifact exception

`.github/workflows/release-authorized.yml` remains outside the routine change-impact optimization boundary.

Its bounded artifact handoffs are intentional release-security controls and remain unchanged:

- raw build artifact;
- independently verified package artifact;
- exact artifact IDs;
- checksum verification;
- attestation before publish;
- one-day retention;
- exact-ID cleanup;
- separated publisher permissions;
- retired legacy Release tombstone.

Do not add Pages or OIDC deployment authority to the Authorized Release publisher.
