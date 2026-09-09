---
name: codebase-design
description: Use when designing or changing module boundaries, public interfaces, abstractions, dependency seams, security boundaries, or test seams.
metadata:
  version: "1.0"
---

# Codebase Design

Use this Skill when the shape of the code is itself a decision, not for ordinary localized implementation.

## Goals

- keep public interfaces small and meaningful
- keep related behavior/knowledge local
- put tests at stable observable seams
- introduce variation points only where real variation exists
- make security/trust boundaries explicit
- avoid speculative abstractions

## Procedure

1. Identify callers and observable behavior that must remain stable.
2. Identify complexity/trust that currently leaks across modules.
3. Choose the narrowest interface that can own that complexity.
4. Add seams only for real substitution, isolation, external integration, deterministic testing, or security boundaries.
5. Check whether the abstraction actually removes complexity.
6. Prefer the smallest design satisfying current requirements.
7. Verify through stable public seams.

For secret-bearing components, design interfaces so callers do not receive secret material unless strictly required. Prefer operations such as store/use/delete over generic read/export interfaces.

Network-capable modules must not receive credential-bearing data unless the Spec explicitly requires and `SECURITY.md` permits that trust boundary.

Adapted from `mattpocock/skills` `codebase-design`.
