---
name: handoff
description: Preserve resumable state when a Loop Engineering planning or implementation session must stop before completion. Write a compact checkpoint to the current GitHub Issue or PR.
metadata:
  version: "1.0"
---

# Handoff

Use only when work must continue in another session or agent. Completed work needs no separate handoff.

## Durable target

Prefer current `[Task]` Issue, implementation PR, `[Decision]`, then `[Spec]` / `[Map]`. Do not create a second progress document when a durable work item already exists.

## Checkpoint

Post only information the next agent cannot cheaply recover:

```md
## Handoff
- Branch / HEAD: `<branch>` / `<sha>`
- PR: <url or none>
- Completed: <what is already true>
- Verification: <checks and result>
- Repository knowledge: <pending durable promotion or none>
- Blocker: <why work cannot finish>
- Next action: <single concrete resume step>
- References: <spec / decisions / docs / safe artifact links>
```

Never include credentials, secrets, TOTP/otpauth/migration payloads, QR screenshots, Wi-Fi passwords, authorization headers, private keys, secret-bearing dumps, or unnecessary personal information.

Do not paste raw logs if they may contain sensitive data; summarize/redact instead.

A resuming agent must re-read the Issue/PR, Parent Spec, linked Decisions, current HEAD, `PROJECT.md`, `SECURITY.md`, and relevant repository truth before editing.

Adapted from `mattpocock/skills` `handoff` for GitHub-backed Loop Engineering.
