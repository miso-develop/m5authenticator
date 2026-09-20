# Agent Instructions

## Highest-priority security rule

Authentication material protection overrides convenience, debugging speed, feature velocity, test convenience, and implementation shortcuts.

Before reading, writing, logging, uploading, attaching, committing, or transmitting any credential-like value, follow `SECURITY.md`.

Never place real authentication material in repository content, Git history, Issues, Pull Requests, comments, logs, artifacts, screenshots, fixtures, examples, or external requests. This includes TOTP secrets, `otpauth://` URIs, Google Authenticator migration payloads/QR images, tokens, passwords, Wi-Fi credentials, private/signing keys, recovery codes, decrypted user stores, and dumps that may contain them.

If a task would require exposing real secret material to complete, stop and redesign the workflow using synthetic/public test data. Do not weaken this rule to unblock development.

## Source of truth

- Prioritize the user's latest explicit instructions.
- `.agent/PROJECT.md` is authoritative for project-wide purpose, scope, constraints, and invariants.
- `SECURITY.md` is authoritative for security-handling rules. If it conflicts with `.agent/PROJECT.md`, apply the stricter rule.
- GitHub Issues / Pull Requests are authoritative for feature/work-item planning, decisions, implementation state, and change history, refined in the order `[Map]` / `[Decision]` / `[Spec]` / `[Task]`.
- The repository is the source of truth for current system state and should express that state through code, configuration, durable documentation, and executable tests/checks as appropriate. Do not rely on closed Issues alone as the source for current specifications.
- Knowledge from Maps / Decisions / Specs that must remain current truth for future work must be promoted into the repository according to the repository knowledge lifecycle in `.agent/WORK-TRACKING.md`.
- A Spec is the contract that must be satisfied; tests, static checks, runtime checks, and reviews are verification evidence. Do not omit the Spec's meaning, intent, or boundaries merely because a verification artifact exists.
- Keep only development process and cross-cutting constraints in `AGENTS.md`.
- Existing code and tests are important evidence, but do not silently change explicit requirements when they conflict with existing implementation.

## Work items

Only an open `[Task]` Issue that actually exists on GitHub may be selected for production-code implementation.

The selected `[Task]` must satisfy all of the following:

- `Parent spec` is explicit.
- Every Issue listed under `Blocked by` is closed.
- Acceptance Criteria are externally observable and assessable.
- If an unfinished PR already handles the same Task, continue that PR/branch rather than creating a new branch.

If no implementable `[Task]` exists, do not infer a task and modify production code. When new work needs to be clarified, use `wayfinder`, `to-spec`, or `to-tickets` according to its size and uncertainty.

See `.agent/WORK-TRACKING.md` for Issue formats, relationships, and handoff rules.

## One implementation iteration

Perform each implementation iteration in this order:

1. Read `.agent/PROJECT.md`, `SECURITY.md`, the target `[Task]`, its parent `[Spec]`, referenced `[Decision]` items/artifacts/comments, and relevant code/tests.
2. Select exactly one ready `[Task]` and establish its title and Issue URL / `owner/repo#number`.
3. If there is no unfinished PR/branch, create a work branch from the latest `main`. Do not commit normal implementation work directly to `main`.
4. Change only the minimum needed for the selected Task and to preserve existing behavior. Use `codebase-design` when a design decision is required and `tdd` when test-first development is appropriate.
5. Explicitly assess impact on secret handling, trust boundaries, logging, artifacts, and network behavior. Security-sensitive changes are subject to the review rules in `SECURITY.md`.
6. Add/update tests with priority on externally observable behavior and run repository-defined required checks. Do not assume verifier-specific contracts or external verifier repositories.
7. Use `code-review` to check requirement compliance, security-policy compliance, and engineering quality. Fix only valid blocking findings and revalidate the affected scope.
8. When green, commit/push and include the parent Spec reference and `Closes #<task-number>` in the PR body.
9. If the repository defines required CI/checks, verify they succeed. Do not claim a check succeeded if it has not been introduced.
10. A Task is complete only after its PR is merged and closes the Task. Do not begin the next Task in the same iteration.

## Security-sensitive implementation constraints

- Do not instruct or record manual tests using real secrets in Public Issues/PRs.
- Do not store production/user QR screenshots as fixtures.
- Treat a secret that is merely base64/hex/URL encoded as still secret.
- Do not emit secret-bearing values through `Serial.print`, browser console, exceptions, assertions, traces, telemetry, or similar outputs.
- Do not send analytics, remote error reports, or external API requests from credential-bearing paths in the Web Provisioner.
- Do not embed a universal encryption key, default user credential, or real service credential in release firmware.
- Do not add a release-mode command/API/UI that exports stored TOTP secrets.
- Changes to secret storage, eFuse, QR import, Web Serial, Factory Reset, firmware update, Wi-Fi credentials, BLE authentication, or the release/signing pipeline are security-sensitive and require review as such.
- Do not commit implementations that temporarily disable security controls. Design required test seams using synthetic keys/material.

## Incomplete / blocked iteration

If the current iteration cannot be completed, stop adding new production changes and use `handoff` to leave a resumable checkpoint on the target `[Task]` Issue or PR.

The checkpoint must not contain secrets or credential-bearing payloads and must include at least the branch/HEAD, PR, completed scope, verification results, blocker, and next concrete action.

## Engineering constraints

- Do not add features, dependencies, abstractions, or large refactors that are not required.
- Do not unintentionally change existing behavior outside the selected Task.
- Do not commit temporary debug code, unnecessary logs, generated output, or credentials.
- Do not record secrets, PATs, private keys, webhook secrets, or similar values in the repository, Issue, PR, or handoff.
- Do not merge while tests are failing.
- Do not remove or weaken existing tests or Acceptance Criteria merely to make verification pass. Contract changes require an explicit `[Spec]` / `[Task]` or user instruction.
- Preserve CRLF when adding `.cmd` files.
- Use `.cmd` for Windows command entrypoints; do not introduce new `.bat` entrypoints.

## Command chaining policy

- Use `&&` command chaining only when it is self-evident that executing the next command after the previous command succeeds introduces no ambiguity in state, side effects, or evidence boundaries.
- For procedures containing state-changing operations or Human evidence, separate commands and explicitly evaluate each command's success/failure before proceeding.
- In Windows `.cmd` helpers, normally add an explicit `if errorlevel 1` check after external commands. Do not combine multiple important operations with `&&`.
- In particular, do not casually chain build → flash, flash → monitor, clean/fullclean → destructive operation, provisioning/reset/eFuse operations, or Human Gate evidence generation.
- When separate entrypoints exist for responsibilities such as build, flash, monitor, or Human Gate helpers, preserve an explicit user action as the boundary between them.

## Supporting rules

- For Issue planning, task decomposition, handoff, or work-item lifecycle, consult `.agent/WORK-TRACKING.md`.
- For security-sensitive changes, always consult `SECURITY.md`.
- Treat `.agents/skills/` as reusable procedures/capabilities for specific tasks.

## Done

A `[Task]` may be treated as complete only when all of the following are true:

- All Acceptance Criteria are satisfied.
- Required automated tests or reproducible verification exist.
- All repository-defined required checks succeed.
- There is no known secret exposure or security regression that violates `SECURITY.md`.
- All blocking findings from `code-review` are resolved.
- There is no known regression or unresolved contradiction.
- The PR is merged and the target Issue is closed through `Closes #<task-number>`.

## Parallel implementation coordination

Because multiple chat/agent sessions or human workers may modify the same repository concurrently, any worker starting implementation or a change to repository current truth must consult `.agent/PARALLEL-WORK.md` and apply its Mandatory preflight and Parallel eligibility gate.

- Treat latest `main`, open/draft PRs, non-main branches, open Tasks, commits, and changed files—not chat conversation or memory—as the shared coordination state.
- Open/draft PRs and non-main branches that can reasonably be mapped to a Task are in-flight work and reserve the Task plus their file/subsystem/shared-contract surfaces.
- Evaluate not only identical files but also semantic conflicts in protocols, schemas, public interfaces, runtime state machines, security boundaries, build/release contracts, and similar shared contracts as hard conflicts.
- Even if a blocker Task has a green PR, it remains unresolved until the PR is merged to `main` and the Issue is closed.
- Allow safe parallel work only when every gate in `.agent/PARALLEL-WORK.md` is satisfied. When uncertain, fail closed and do not parallelize.
- Re-run the relevant preflight not only at Task selection but also before first write, before scope expansion, before push/PR creation, and immediately before merge as applicable.
- If `main` advances during the work, re-evaluate semantic/dependency overlap as well as file overlap and update the branch to latest `main` and reverify when necessary.
- Process/documentation-only changes follow the same conflict checks and must not be committed directly to protected `main`.
- For a new production Task, after preflight and before meaningful implementation, create remote `task/<issue-number>` from the observed latest main as the atomic claim. If that branch already exists, do not bypass ownership with another branch; follow the ownership rules in `.agent/WORK-TRACKING.md`.
