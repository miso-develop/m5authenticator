# Loop Engineering

このrepositoryのLoop Engineering運用は、次をcanonical ruleとして扱います。

- `AGENTS.md`: agentが守る横断的なimplementation / security / completion constraints
- `agent/WORK-TRACKING.md`: Map → Decision → Spec → Task lifecycle、dependency、handoff、repository knowledge promotion
- `agent/PARALLEL-WORK.md`: 複数chat / agent / human workerによるparallel implementation coordination
- `agent/PARALLEL-WORK-CHECKLIST.md`: parallel preflight / push / merge時の短縮チェック

特に複数workerで同一repositoryを並列実装する場合、`agent/PARALLEL-WORK.md` のMandatory preflightとParallel eligibility gateを実装開始前に必ず適用します。
