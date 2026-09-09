# Bundled Agent Skills

These skills support the repository's Loop Engineering workflow.

## Planning

- `wayfinder`: create and work `[Map]` / `[Decision]` planning graphs
- `to-spec`: synthesize settled decisions into a `[Spec]`
- `to-tickets`: decompose a `[Spec]` into vertical `[Task]` issues
- `loop-status`: summarize the current GitHub-backed Loop state without mutating it

## Implementation

- `implement`: implement exactly one ready `[Task]`
- `codebase-design`: make bounded module/interface/seam decisions
- `tdd`: use test-first development at stable observable seams
- `code-review`: review behavior, engineering quality, and security policy
- `handoff`: leave durable resumable state on the active Issue/PR

`AGENTS.md`, `PROJECT.md`, `SECURITY.md`, and `agent/WORK-TRACKING.md` remain authoritative over these skills.

Security handling is never relaxed by a Skill. Real authentication material must not enter repository content, GitHub work items, logs, artifacts, fixtures, screenshots, or external requests.

See `THIRD-PARTY-NOTICES.md` for upstream attribution.
