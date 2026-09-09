---
name: loop-status
description: Summarize the current ticket-driven Loop Engineering state for a repository. Use for current progress, remaining work, ready/blocked Tasks, planning items, open PRs, blockers, closeout-pending Specs, or next work.
metadata:
  version: "1.1"
---

# Loop Status

Build a current-state view from GitHub Issues / Pull Requests. Do not maintain or infer a separate progress ledger.

## Collect active work

Read current GitHub state and collect open `[Map]`, `[Decision]`, `[Spec]`, `[Task]` Issues, open PRs, and relevant latest `## Handoff` comments.

For each open Task resolve Parent Spec, declared `Blocked by` Issues, blocker state, and any open PR that closes the Task.

Classify:

- **Ready**: Task open, all declared blockers closed, no conflicting implementation. Existing resumable PR means resume it rather than create a new branch.
- **Blocked**: at least one declared blocker is open or a required reference cannot be resolved.

Do not invent dependencies from issue ordering, numbering, title similarity, or intuition.

## Planning / closeout

Report why Maps/Decisions/Specs remain open. A Spec whose indexed Tasks are all closed is **Closeout pending**, not automatically complete; Requirements, verification evidence, security policy, and repository knowledge promotion still require semantic review.

Security-sensitive Specs must not be reported complete when a known `SECURITY.md` violation or unresolved exposure exists.

## Report order

1. Summary
2. Ready Tasks
3. Blocked Tasks
4. Closeout pending Specs
5. Planning
6. Open PRs
7. Latest handoffs
8. Next action

Status requests are read-only unless the user separately asks to mutate project state.
