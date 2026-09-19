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
