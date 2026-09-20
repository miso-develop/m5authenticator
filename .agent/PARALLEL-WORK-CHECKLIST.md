# Parallel Work Checklist

This is the abbreviated checklist for implementation workers. `PARALLEL-WORK.md` is authoritative for conflict-assessment details, and `WORK-TRACKING.md` is authoritative for the Task claim lifecycle.

## Before Task claim / first write

- [ ] Retrieved the latest `main` SHA
- [ ] Reviewed every open/draft PR
- [ ] Reviewed non-main branches
- [ ] Confirmed every `Blocked by` entry for the candidate Task is closed
- [ ] Confirmed no PR/branch already claims the same Task
- [ ] Confirmed planned changed files do not overlap reserved files
- [ ] Confirmed there is no semantic conflict involving protocol/schema/interface/state machine/security/build or similar shared contracts
- [ ] Do not depend on an unmerged contract
- [ ] Confirmed the Task can be implemented and verified from latest main alone
- [ ] Created remote `task/<issue-number>` from the observed latest main SHA to claim the Task atomically
- [ ] Re-read latest main / open PRs / branches after the claim and confirmed ownership state did not change
- [ ] After the first meaningful commit, create a Draft PR early and explicitly include `Parent spec` and `Closes #<task-number>`

## Before scope expansion

- [ ] Re-read GitHub state before touching a new shared file/header/protocol/schema/workflow/lockfile
- [ ] Confirmed there is no conflict with a newly reserved surface

## Before push / PR

- [ ] Re-read latest main
- [ ] Checked whether new open PRs/branches appeared
- [ ] If main advanced, re-evaluated both file and semantic overlap

## Before merge

- [ ] Confirmed the expected PR head SHA
- [ ] Confirmed latest main HEAD
- [ ] Rechecked changed-file overlap
- [ ] Rechecked semantic/dependency conflict
- [ ] Required checks are green on the exact head
- [ ] If main advanced and assumptions changed, updated the branch and completed re-verification

If any item cannot safely be answered YES, do not proceed with parallel merge/implementation.
