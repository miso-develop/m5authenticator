# Parallel Work Checklist

実装worker向けの短縮チェックです。競合判定の詳細は `PARALLEL-WORK.md`、Task claim lifecycleは `WORK-TRACKING.md` を正とします。

## Before Task claim / first write

- [ ] latest `main` SHAを取得した
- [ ] open/draft PRを全件確認した
- [ ] non-main branchを確認した
- [ ] candidate Taskの`Blocked by`がすべてclosedである
- [ ] 同じTaskをclaimするPR/branchがない
- [ ] planned changed filesとreserved filesが重ならない
- [ ] protocol/schema/interface/state machine/security/build等のsemantic conflictがない
- [ ] 未merge contractを前提にしない
- [ ] latest mainだけからTaskを実装・検証できる
- [ ] observed latest main SHAからremote `task/<issue-number>` branchを作成してatomic claimした
- [ ] claim後にlatest main / open PR / branchesを再取得し、ownership stateが変わっていないことを確認した
- [ ] first meaningful commit後はDraft PRを早期作成し、`Parent spec` と `Closes #<task-number>` を明示する

## Before scope expansion

- [ ] 新たにshared file/header/protocol/schema/workflow/lockfileへ触れる前にGitHub stateを再確認した
- [ ] 新しいreserved surfaceとの競合がない

## Before push / PR

- [ ] latest mainを再取得した
- [ ] 新しいopen PR/branchが増えていないか確認した
- [ ] mainが進んでいる場合、file + semantic overlapを再評価した

## Before merge

- [ ] expected PR head SHAを確認した
- [ ] latest main HEADを確認した
- [ ] changed-file overlapを再確認した
- [ ] semantic/dependency conflictを再確認した
- [ ] required checksがexact headでgreen
- [ ] mainが進んで前提が変わった場合、branch更新と再検証を完了した

どれか1つでも安全にYESと言えない場合、並列merge/implementationを進めません。
