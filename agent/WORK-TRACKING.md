# Work Tracking

Loop Engineeringのplanning / implementation状態はGitHub Issues / Pull Requestsへ集約します。repository内に別の進捗台帳を作りません。

## Source-of-truth boundary

```text
GitHub Issues / Pull Requests
    = planning / decision / implementation state と変更履歴

Repository
    = 現在のsystem state
```

repository current truthは必要に応じてcode、configuration、durable documentation、tests/static checks等で表現します。

closed Issueは判断履歴として重要ですが、将来も有効なarchitecture/security/contractを理解するために過去Issue探索を必須にしてはいけません。Map / Decision / Specで得た知識のうち、現在も有効なsystem truthはrepositoryへpromotionします。

## Canonical work item flow

```text
[Map]
  ↓ resolves unknowns through [Decision]
[Decision]
  ↓ settled outcomes
[Spec]
  ↓ implementation decomposition
[Task]
  ↓ one branch / one PR / merge
repository current truth
```

すべての変更でMapを作る必要はありません。

- 小さく既に要件が確定している変更: `[Spec]` から開始可能
- 単一の明確なimplementation change: 既存 `[Spec]` 配下に `[Task]`
- 大きい、曖昧、複数の判断を含む変更: `[Map]` から開始

## Manual issue creation

GitHub UIから作成する場合は `.github/ISSUE_TEMPLATE/` のFormsを使用します。

- `Loop Map` → `[Map]`
- `Loop Decision` → `[Decision]`
- `Loop Spec` → `[Spec]`
- `Loop Task` → `[Task]`

Agent/APIがIssueを直接作成する場合も、以下のcanonical body形式に従います。

## Dependency notation

`Blocked by` は次のどちらかだけを使用します。

```md
## Blocked by
- None
```

または:

```md
## Blocked by
- #123
- #456
```

- same-repository standalone `#<number>` を使う
- self dependencyを禁止する
- dependency cycleを作らない
- Task blockerはTask、Decision blockerはDecisionを参照する

## Repository knowledge lifecycle

Map / Decision / Specで得た情報について、とくにSpec closeout時に次を問います。

> この情報は、今後の開発でも「現在のsystem state」として知られている必要があるか？

YESならrepository current truthへpromotionします。候補は次です。

- `PROJECT.md`
- `SECURITY.md`
- architecture/security/design docs
- code / configuration
- durable specification
- automated tests / static checks

Issue本文をそのままdocumentへ複製しません。二重正本を避け、現在有効なcontract/rationaleだけを適切な場所へ反映します。

### Map knowledge

`[Map]` は原則Exploration Mapです。問題空間、unknown、dependency、decision pointを構造化する一時的planning artifactであり、EpicやTask一覧ではありません。

探索結果としてsystem structure自体を将来も理解する必要がある場合、その部分だけarchitecture documentation等へpromotionします。

### Decision knowledge

Decisionは1つの判断を確定するwork itemです。

repositoryへpromotionすべき代表例:

- architecture / dependency direction
- security / trust boundary
- credential handling policy
- fail-closed policy
- compatibility policy
- subsystem ownership
- 将来変更時に現在案の理由を知る必要がある判断

Decisionは実装進捗を追うために開け続けません。answer/evidenceが確定し、必要なpromotionが完了または下流Spec/Taskへ明示的に引き継がれたらcloseします。

### Spec and verification

```text
Spec
    = systemが満たすべきcontract

Test / Static Check / Runtime Check / Review
    = contract成立を確認するevidence
```

`Spec != Test` です。

architecture/security/operational ruleはtestだけで完全表現できない場合があります。その場合はcode/configuration/documentation/review/static checkを組み合わせます。

### Task knowledge

Taskは実装単位です。Task Issue自体を恒久documentationとしてrepositoryへ保存しません。履歴はTask Issue → PR → commit historyに残します。

## Work item types

### `[Map]`

大きい・曖昧・複数sessionにまたがるworkのExploration Mapです。`wayfinder` が作成します。

Body:

```md
## Destination
<map完了時に何が決まっていればよいか>

## Decisions so far
- None yet

## Not yet specified
- <まだquestionとして切れないin-scopeのfog>

## Out of scope
- <今回扱わないこと>
```

Mapは次を満たしたらcloseします。

- unresolvedなin-scope Decisionがない
- `Not yet specified` が空またはout of scopeへ移された
- downstream `[Spec]` が作成・linkされている

Taskやimplementation完了までは待ちません。

### `[Decision]`

Map配下で1つのquestion / investigationを解決するIssueです。production implementation taskではありません。

Body:

```md
## Parent map
#<map-number>

## Question
<このIssueで決める1つのquestion>

## Blocked by
- None
```

解決時:

1. answer / evidenceをcommentに残す
2. durable repository knowledgeか判定する
3. 必要なpromotionまたはdownstream ownershipを明示する
4. Decisionをcloseする
5. Parent Mapの`Decisions so far`へlinkする

### `[Spec]`

実装前に確定したfeature contractです。`to-spec` が作成します。

Body:

```md
## Problem
<user perspectiveの問題>

## Outcome
<実現する結果>

## Requirements
- <observable requirement>

## Decisions
- <settled decision>

## Verification
- <observable check / test seam>

## Out of scope
- <明示的に扱わないこと>

## References
- `PROJECT.md`
- `SECURITY.md` when applicable
- <Map / Decision / external spec>

## Repository knowledge
<initial advisory assessment>

## Implementation tasks
- [ ] #<task-number> <task title>
```

Security-sensitive featureでは `SECURITY.md` を必ずReferencesに含めます。

SpecはImplementation Tasksがすべてclosedになった後、Requirements、verification、repository knowledge promotionを再評価してcloseします。

### `[Task]`

Taskは1 iteration / 1 coherent PRで実装できるvertical sliceです。

Body:

```md
## Parent spec
#<spec-number>

## What to build
<このTaskだけで実装すること>

## Acceptance criteria
- [ ] <外部から判定可能な条件>

## Blocked by
- None
```

Taskは次を満たす必要があります。

- Parent Specが実在する
- Parent Specの`Implementation tasks`に列挙される
- blockerがすべてclosedになるまでproduction implementationを開始しない
- Acceptance Criteriaがobservableである
- unrelated cleanupを含めない

## Implementation lifecycle

1. exact `[Task]` とParent `[Spec]` を読む
2. `PROJECT.md` と `SECURITY.md` を読む
3. blockerと既存PR/branchを確認する
4. latest `main` からTask branchを作る、または既存branchを継続する
5. smallest complete sliceを実装する
6. targeted tests/checksを実行する
7. security-sensitive changeならcredential flow、logging、artifact、network boundaryを明示的にreviewする
8. code reviewを行う
9. PRを作成し `Parent spec: #...` と `Closes #...` を記載する
10. required checks green後にmergeする
11. mergeによってTaskをcloseする
12. final Taskの場合はParent Spec closeoutとrepository knowledge promotionを確認する

Verifier固有framework、外部Verifier repository、`.verifier` contractはこのrepositoryのLoop Engineering lifecycleには含めません。repository自身にCI/checkを追加した場合のみ、そのrepository-defined checksをrequired verificationとして扱います。

## Handoff

session/blockerによりTaskを完了できない場合、対象IssueまたはPRへcheckpointを残します。

最低限:

- branch / HEAD
- PR
- completed scope
- verification performed
- blocker
- next concrete action

**Secret、credential、QR payload、Wi-Fi password、private dump等をhandoffへ記載してはいけません。**

## Security-specific work tracking

Securityに関するDecisionは、単なるIssue履歴で終わらせず、将来の実装を拘束する内容であれば `PROJECT.md` / `SECURITY.md` / durable design document / executable checkへpromotionします。

特に次はdurable knowledge候補です。

- secret storage / encryption architecture
- eFuse policy
- provisioning trust boundary
- Web Provisioner network policy
- secret export prohibition
- Factory Reset semantics
- firmware update secret-retention policy
- BLE authentication model
- release/signing model
