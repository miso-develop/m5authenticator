# Parallel Coordination Example

この文書は説明例です。canonical ruleは `agent/PARALLEL-WORK.md` です。

## Situation

- `main`: current merged truth
- PR A: Task #10、trusted-time / TOTP / provisioning protocolを変更中
- candidate Task B: device UI
- candidate Task C: browser Web Serial management UI

## Evaluation

Task Bが `Blocked by: #10` を持つ場合、PR AがgreenでもTask Bは開始しません。#10がmainへmergeされIssueがclosedになるまでblockerはopenです。

Task Cが`time.sync`等のprotocol consumerを実装する場合、PR Aとfile overlapがなくても、未merge protocol contractへの依存があるためsemantic conflictです。PR A merge後にlatest mainから開始します。

一方、別workerが`agent/PARALLEL-WORK.md`のようなprocess-only documentだけを変更し、PR Aのfiles / product contractへ触れない場合は、preflightで独立性を確認したうえで並列進行できます。
