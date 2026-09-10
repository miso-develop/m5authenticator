# Parallel Work Coordination

この文書は、複数のChatGPT chat / agent session / human workerが同一repositoryで同時にLoop Engineeringを進める場合のcanonical coordination ruleです。

目的は、中央の会話共有や手動の「今これを触っています」という申告に依存せず、GitHub上の観測可能なstateからin-flight workを判定し、同じTaskの重複実装・file conflict・semantic conflict・古いbaseからの上書きを防止することです。

このruleは `AGENTS.md` のimplementation lifecycleおよび `agent/WORK-TRACKING.md` を補完します。security ruleと矛盾する場合は `SECURITY.md` を優先します。

## Core principle

各chat / agent sessionは独立したworkerとして扱います。

workerは、production implementationまたはrepository current truthを変更する作業を開始する前に、他workerの状態を会話から推測してはいけません。必ずGitHubの最新stateから判定します。

```text
GitHub open Issues / open PRs / branches / commits / changed files
    = shared coordination surface

chat history / local assumption
    = coordination source of truthではない
```

「別chatで作業しているかもしれないが確認できない」は、競合がないという意味ではありません。確認できるGitHub stateを使ってfail closedに判定します。

## Terminology

- **worker**: 1つのchat、agent session、human implementation session。
- **candidate Task**: 今回workerが着手を検討しているopen `[Task]` Issue。
- **in-flight work**: mainへ未mergeの実装作業。open/draft PR、またはTaskとの対応が合理的に判別できるnon-main branchを含む。
- **claimed Task**: in-flight workによって既に実装対象として占有されているTask。
- **reserved surface**: in-flight workが変更中、または意味的にownershipしているfile / directory / interface / schema / protocol / build surface。
- **hard conflict**: 並列着手を禁止する競合。
- **semantic conflict**: file pathが異なっても、同じcontract・interface・state machine・schema等を同時変更する競合。

## Mandatory preflight

workerはbranch作成、production code変更、durable architecture/configuration変更の**前**に毎回次を行います。

1. latest `main` HEAD SHAを取得する。
2. `main` 向けのopen PRをDraftを含めてすべて確認する。
3. non-main branchを確認する。
4. open `[Task]` Issueと各Taskの `Blocked by` を確認する。
5. 各open PRについて、head branch、head SHA、base SHA、linked/closing Task、changed filesを確認する。
6. PRがないnon-main branchについて、branch名、commit message、mainとの差分からTaskとの対応を可能な範囲で判定する。
7. mainのrecent commit / merge状況を確認し、candidate Taskの前提となるTaskがmerge済みか確認する。
8. candidate Taskとin-flight workのdependency・changed files・semantic ownershipを比較する。
9. 下記のParallel eligibility gateを満たした場合だけbranchを作成または既存branchを継続する。

preflight結果が途中で不明確になった場合、都合のよい推測で着手してはいけません。対象Taskをblocked扱いにするか、競合しない別Taskを選びます。

## How to identify in-flight work

### Open PR

open PRはDraftを含め常にin-flight workです。

Task ownershipは次の順で判定します。

1. PR bodyの `Closes #<number>` / `Fixes #<number>` / explicit Task reference
2. branch名のTask number
3. PR title / bodyとTask title / scopeの一致
4. changed filesとTask Acceptance Criteriaの一致

1で明示されたTaskがある場合、それをcanonical claimとします。

### Branch without PR

PR未作成のnon-main branchも無視してはいけません。

次のsignalを組み合わせ、Taskが合理的に一意ならin-flight claimとして扱います。

- `task/<number>-...`, `feat/<number>-...`, `issue-<number>-...` 等のbranch名
- branch上のcommit message
- mainとのchanged files
- open Taskのscope

Task mappingが一意に確定できなくても、branchのchanged files / semantic surfaceはreservedとして扱います。

古い、abandonedと思われるbranchでも、GitHub上で明示的に不要と判断できない限り「存在しないもの」として扱ってはいけません。安全に判断できない場合は人間確認またはbranch cleanupを先に行います。

## Reservation model

in-flight workは次の3層を予約します。

### 1. Exact file reservation

open PRまたはbranchが変更しているfileはreservedです。

candidate Taskが同じfileを変更する必要がある場合、原則hard conflictです。

例外は、双方の変更が完全に独立したgenerated metadata等であり、rebase後も自動的に安全と証明できる場合だけです。「たぶんmergeできる」は証明になりません。

### 2. Directory / ownership reservation

変更fileだけでなく、そのTaskが明示的に所有するcoherent subsystemも確認します。

例:

- provisioning protocol implementation
- account storage schema / migration
- trusted-time state machine
- TOTP core
- device input/UI behavior
- Web Serial transport/session
- release/build workflow

同じsubsystemのpublic interface、state transition、ownership boundaryを別workerが同時に変更する場合、fileが異なってもsemantic conflictです。

### 3. Contract reservation

次はshared contractとして特に強く予約します。

- protocol vocabulary / version / wire format
- storage schema / partition layout / migration behavior
- public C/C++ headers and TypeScript interfaces used across subsystems
- security/trust boundary
- runtime state machine
- device input mapping
- release artifact layout
- CI/build contract and shared workflow
- dependency versions / lockfiles when both branches need dependency changes

in-flight Taskがこれらを変更している場合、そのcontractをconsumerとして必要とするdownstream Taskは、contractがmainへmergeされるまで原則開始しません。

## Hard conflict conditions

次のいずれかが成立したらcandidate Taskの新規implementation開始を禁止します。

1. 同じTaskをclaimするopen PRまたはactive branchがある。
2. candidate Taskの `Blocked by` にopen Issueがある。
3. blocker TaskのPRがgreenでもまだmainへmergeされていない。
4. candidate Taskがin-flight workと同じfileを変更する必要がある。
5. candidate Taskがin-flight workと同じshared contractを変更する。
6. candidate Taskが、in-flight workで新設・変更中のinterfaceを前提にする。
7. candidate Taskの実装方法が、in-flight branchの未merge設計判断によって変わる可能性が高い。
8. candidate branch作成後にmainが進み、そのmain更新がcandidate Taskのreserved surfaceと重なる。
9. branch/PR/Issueの対応が不明確で、安全に独立と判定できない。

hard conflict時は、競合branchへ勝手にcommitしない、相手workerのPRを勝手に作り直さない、同等機能を別実装で迂回しないものとします。

## Parallel eligibility gate

candidate Taskは次を**すべて**満たす場合だけ別workerで並列実装できます。

- candidate Task自身がreadyで、すべての`Blocked by`がclosed。
- 同じTaskをclaimするin-flight workがない。
- candidate Taskのplanned changed filesが既存reserved filesと重ならない。
- candidate Taskのsemantic ownershipが既存reserved subsystemと重ならない。
- candidate Taskが未merge contractをconsumerとして必要としない。
- candidate TaskのAcceptance Criteriaを、他in-flight branchの内容を仮定せずmainだけから実装・検証できる。
- branchをlatest mainから作成できる。
- required CI/checksを独立して評価できる。

このgateの1項目でも満たさない場合は並列化しません。

## Planned change surface

workerはcandidate Taskの実装開始前に、少なくとも次を頭の中または作業記録として特定します。

- primary directories/files expected to change
- public/shared interfaces expected to change
- schema/protocol/build/security contractへの影響
- likely tests/workflows expected to change

完全なfile listを事前に固定する必要はありません。ただし、実装中にplanned surface外のshared areaを触る必要が判明したら、その時点で再度GitHub preflightを行います。

## Recheck points

preflightはiteration開始時の1回だけでは不十分です。次の時点で必ず再確認します。

### Before first write

branch作成後、最初のmeaningful change前にopen PR / branch stateが変わっていないことを確認します。

### Before expanding scope

新しいdirectory、shared header、schema、protocol、workflow、lockfile等へ変更範囲を広げる前にreservationを再評価します。

### Before push / PR creation

latest mainと他open PRを再取得します。別workerが後から競合surfaceをclaimしていた場合、pushを増やす前に停止して解消方針を決めます。

### Before merge

PR merge直前に最低限次を確認します。

- PR head SHAが想定通り
- main HEADが前回確認から進んでいないか
- candidate branchとlatest mainのmergeability
- 新たなopen PRとのchanged-file overlap
- shared contractのsemantic conflict
- required checksがexact headでgreen

mainが進んでいた場合、単にGitHubが`mergeable`だからという理由だけでmergeしません。main側の変更内容を確認し、必要ならupdate/rebase相当を行い、再検証します。

## Main advanced while working

作業中にmainが進んだ場合は次のように扱います。

1. old baseとlatest mainのdiffを確認する。
2. latest mainでmergeされたTask/PRを特定する。
3. candidate branchとのfile overlapを確認する。
4. file overlapがなくてもcontract / dependency / behavior overlapを確認する。
5. overlapがある、または前提が変わった場合はbranchをlatest mainへ更新して再検証する。
6. overlapがなくてもPR本文やverification説明が古くなった場合は更新する。

「branch作成時には競合していなかった」はmerge許可の根拠になりません。

## Conflict resolution priority

競合が発生した場合は次の優先順位で処理します。

1. 既にmainへmerge済みのstate
2. 先にopen PRとしてTaskをclaimしているwork
3. PR未作成だが明確にTaskをclaimしているactive branch
4. まだbranchを作っていないcandidate work

後発workerが先行workを無断で置換しません。

先行workが明らかにabandoned / incorrectである場合も、勝手に競合実装を進めるのではなく、Issue/PR stateを明示的に整理してからownershipを移します。

## One Task, one implementation line

1つのTaskには同時に複数のimplementation branch / PRを作りません。

既存PRに問題がある場合は原則そのbranch/PRを修正します。完全な再実装が必要な場合は、旧PRをcloseし、ownership移行理由をIssue/PRに残した後で新branchを作成します。

## Cross-Task integration

並列実装可能なTask同士でも、integrationはmainを介します。

worker Aの未merge branchをworker Bのbaseにしてはいけません。ただし、明示的にstacked PRを採用するDecision/Taskがある場合を除きます。

通常:

```text
main ── Task A branch ── PR A ── merge
  └── Task B branch ── PR B ── merge
```

禁止される暗黙stack:

```text
main ── Task A branch
          └── Task B branch
```

これによりTask間のhidden dependencyを防ぎます。

## Rules for documentation / process-only changes

production Taskと独立したagent/process documentation変更も、open implementation PRと同じpreflightを行います。

ただし、変更対象が `AGENTS.md` / `agent/` 等のprocess-only surfaceに限定され、in-flight product PRとfile/semantic conflictがない場合は、product Taskの`Blocked by` chainとは独立して進められます。

process rule変更もprotected `main` へ直接commitせず、branch / PR経由を原則とします。

## Minimal evidence in PR

並列実装したPRでは、必要に応じて本文またはreviewで次を説明できる状態にします。

- branchを作成したmain SHA
- 同時点の主要in-flight PR
- なぜfile / semantic conflictがないと判断したか
- 作業中にmainが進んだ場合の再評価結果

毎回長いcoordination reportを残す必要はありませんが、競合判断が重要な場合は後から追跡できるevidenceを残します。

## Fail-closed examples

### Example: safe parallel work

- PR A: firmware storage implementation
- Task B: browser-only QR parser
- changed directoriesがfirmware storageと`web/src/import`に分離
- shared protocol/schemaを同時変更しない
- Task BはTask Aをblockerに持たない

→ Parallel eligibility gateを満たせば並列実装可能。

### Example: same file

- PR Aが`firmware/main/app_main.cpp`を変更中
- Task Bもdevice runtime wiringのため同file変更が必要

→ hard conflict。PR A merge後にTask Bを開始する。

### Example: different files but semantic conflict

- PR AがNDJSON `time.sync` protocolを設計・実装中
- Task Bが別fileでWeb Serial clientの`time.sync` consumerを実装予定
- Task Bの正しいbehaviorがPR Aの未mergecontractに依存

→ file overlapがなくてもhard conflict。contractがmainへmergeされるまで待つ。

### Example: independent process change

- PR Aがfirmware trusted-time/TOTPを変更中
- process PRが`agent/PARALLEL-WORK.md`だけを追加
- product contractやPR Aのchanged filesに触れない

→ process PRは並列進行可能。

## Required worker behavior summary

workerは常に次を守ります。

1. GitHub stateを見てからTaskを選ぶ。
2. open PRだけでなくbranchも見る。
3. file conflictだけでなくsemantic conflictを見る。
4. blockerがPR段階なら「ほぼ完了」ではなく未完了として扱う。
5. 未merge implementationを前提に別Taskを作らない。
6. mainが進んだら再評価する。
7. 不明確なら並列化しない。
8. merge直前にもう一度競合を確認する。

並列性よりcorrectnessとmerge safetyを優先します。安全に独立と証明できるTaskだけを並列化します。
