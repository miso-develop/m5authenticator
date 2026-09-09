# Agent Instructions

## Highest-priority security rule

Authentication material protection overrides convenience, debugging speed, feature velocity, test convenience, and implementation shortcuts.

Before reading, writing, logging, uploading, attaching, committing, or transmitting any credential-like value, follow `SECURITY.md`.

Never place real authentication material in repository content, Git history, Issues, Pull Requests, comments, logs, artifacts, screenshots, fixtures, examples, or external requests. This includes TOTP secrets, `otpauth://` URIs, Google Authenticator migration payloads/QR images, tokens, passwords, Wi-Fi credentials, private/signing keys, recovery codes, decrypted user stores, and dumps that may contain them.

If a task would require exposing real secret material to complete, stop and redesign the workflow using synthetic/public test data. Do not weaken this rule to unblock development.

## Source of truth

- ユーザーの最新かつ明示的な指示を最優先する。
- project全体の目的・scope・制約・不変条件は `PROJECT.md` を正とする。
- security handling rulesは `SECURITY.md` を正とし、`PROJECT.md` と矛盾する場合はより厳しい方を適用する。
- feature / work itemのplanning・decision・implementation stateと変更履歴はGitHub Issues / Pull Requestsを正とし、`[Map]` / `[Decision]` / `[Spec]` / `[Task]` の順に具体化する。
- repositoryは現在のsystem stateのsource of truthとし、必要に応じてcode、configuration、durable documentation、executable tests/checksで表現する。closed Issueだけを現在仕様の参照元にしない。
- Map / Decision / Specから得た知識のうち将来もcurrent truthとして必要なものは、`agent/WORK-TRACKING.md` のrepository knowledge lifecycleに従ってrepositoryへ反映する。
- Specは満たすべきcontractであり、test・static check・runtime check・reviewはverification evidenceである。verification artifactだけを理由にSpecの意味・意図・境界を省略しない。
- `AGENTS.md` には開発プロセスと横断的な制約だけを置く。
- 既存コードやテストは重要な根拠だが、明示された要件と矛盾する場合に要件を黙って変更しない。

## Work items

production codeの実装対象として選択できるのは、GitHub上に実在するopenな `[Task]` Issueだけとする。

選択する `[Task]` は次を満たす必要がある。

- `Parent spec` が明示されている。
- `Blocked by` に記載されたIssueがすべてclosedである。
- Acceptance Criteriaが外部から判定可能な粒度である。
- 同じTaskを扱う未完了PRがある場合は、新規branchを作らずそのPR / branchを継続する。

実装可能な `[Task]` がない場合はtaskを推測してproduction codeを変更しない。新しいworkを具体化する必要がある場合は、規模と不確実性に応じて `wayfinder`、`to-spec`、`to-tickets` を使用する。

Issueの形式・関係・handoff規則は `agent/WORK-TRACKING.md` を参照する。

## One implementation iteration

各implementation iterationでは次を順に行う。

1. `PROJECT.md`、`SECURITY.md`、対象 `[Task]`、親 `[Spec]`、参照された `[Decision]` / artifact / comments、関連コードとテストを確認する。
2. readyな `[Task]` を正確に1つだけ選び、titleとissue URL / `owner/repo#number` を確定する。
3. 未完了PR / branchがなければ最新 `main` から作業branchを作る。通常の実装を `main` へ直接commitしない。
4. 選択taskと既存挙動維持に必要な最小限だけ変更する。設計判断がある場合は `codebase-design`、test-firstが適切な場合は `tdd` を使用する。
5. secret handling / trust boundary / logging / artifact / network behaviorへの影響を明示的に確認する。security-sensitive changeは `SECURITY.md` のreview対象とする。
6. 外部から観測可能な挙動を優先してテストを追加・更新し、repositoryで定義されたrequired checksを実行する。Verifier固有のcontractや外部Verifier repositoryを前提にしない。
7. `code-review` で要件適合、security policy適合、engineering qualityを確認し、有効なblocking findingだけを修正して影響範囲を再検証する。
8. greenであればcommit / pushし、PR本文に親Specへの参照と `Closes #<task-number>` を入れる。
9. repositoryでrequiredと定義されたCI/checkがある場合はsuccessを確認する。未導入のcheckを成功したものとして扱わない。
10. taskはPR mergeによってcloseされて初めて完了とする。同じiterationで次のtaskへ進まない。

## Security-sensitive implementation constraints

- Real secretsを使うmanual testをPublic Issue/PR上で指示・記録しない。
- Production/user QR screenshotをfixtureとして保存しない。
- Secretをbase64/hex/URL encodeしただけの値もsecretとして扱う。
- `Serial.print`, browser console, exception, assertion, trace, telemetry等にsecret-bearing valueを出さない。
- Web Provisionerのcredential-bearing pathからanalytics / remote error reporting / external API送信を行わない。
- Release firmwareにuniversal encryption key、default user credential、real service credentialを埋め込まない。
- Release modeで保存済みTOTP secretをExportするcommand/API/UIを追加しない。
- Secret storage、eFuse、QR import、Web Serial、Factory Reset、firmware update、Wi-Fi credentials、BLE authentication、release/signing pipelineの変更はsecurity-sensitiveとしてreviewする。
- Security controlを一時的に無効化する実装をcommitしない。必要なtest seamはsynthetic key/materialで設計する。

## Incomplete / blocked iteration

現在のiterationを完了できない場合は、新しいproduction changeを増やすのを止め、`handoff` を使用して対象 `[Task]` IssueまたはPRへ再開checkpointを残す。

checkpointにはsecretやcredential-bearing payloadを含めず、少なくともbranch / HEAD、PR、完了済み範囲、検証結果、blocker、次の具体的操作を記録する。

## Engineering constraints

- 要件にない機能、依存関係、抽象化、大規模refactorを追加しない。
- 選択task外の既存挙動を意図せず変更しない。
- 一時debug code、不要log、生成物、credentialをcommitしない。
- secret、PAT、private key、webhook secret等をrepository、Issue、PR、handoffへ記録しない。
- テスト失敗中のmergeを行わない。
- 検証を通す目的だけで既存testやAcceptance Criteriaを削除・弱体化しない。contract変更には明示された `[Spec]` / `[Task]` またはユーザー指示を必要とする。
- `.cmd` を追加する場合はCRLFを維持する。
- Windows command entrypointは `.cmd` に統一し、`.bat` は新規導入しない。

## Supporting rules

- Issue planning、task分解、handoff、work item lifecycleを扱う場合は `agent/WORK-TRACKING.md` を参照する。
- Security-sensitive changeでは `SECURITY.md` を必ず参照する。
- `.agents/skills/` は特定タスク向けの再利用可能な手順・能力として扱う。

## Done

`[Task]` を完了扱いにできるのは、次をすべて満たす場合だけとする。

- Acceptance Criteriaをすべて満たす。
- 必要な自動テストまたは再現可能な検証がある。
- repositoryで定義されたrequired checksがすべて成功する。
- `SECURITY.md` に違反する既知のsecret exposure / security regressionがない。
- `code-review` のblocking findingが解消されている。
- 既知のregressionや未解決矛盾がない。
- PRがmergeされ、`Closes #<task-number>` により対象Issueがclosedになっている。
