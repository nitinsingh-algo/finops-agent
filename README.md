# Algo-Finops — IAC Agent (step 1)

LangGraph sub-agent that ingests a GitHub event, clones the repo into an isolated workspace, sandboxes it, and emits a `ProjectBlueprint` later plan/apply stages can consume.

## Step 1 pipeline

```
IAC Agent
  → GitHub Webhook  ↔  Token Setup  ↔  DB
  → Isolated clone  →  Sandbox
  → Analyze project structure  ↔  Lightweight analysis engine
  → ProjectBlueprint
```

Each box is a LangGraph node. Stages are registered dynamically, so plan/apply can be appended without rewriting ingest:

```python
graph = build_iac_graph(runtime, stages=[IngestStage(), PlanStage(), ApplyStage()])
```

## Architecture

- **Ports & adapters** — graph nodes depend on `TokenStore`, `RepoCloner`, `SandboxProvider`, `AnalysisEngine`, `RunStore`. Swap GitHub App tokens, Docker isolation, or Postgres without touching the graph.
- **Plugin analyzers** — Terraform, Terragrunt, Pulumi, CDK, CloudFormation, Kubernetes, Helm, Ansible, Docker, Compose, Bicep, plus runtime detection. Add a class and register it, or ship an `algo_finops.iac.analyzers` entry point.
- **Secrets stay out of state** — LangGraph checkpoints store run ids only. Tokens are resolved at the adapter boundary and redacted from git errors.
- **Blueprint contract** — `ProjectBlueprint` is the only output later stages should read.

## Run

```bash
python3.14 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
cp .env.example .env
# set IAC_GITHUB_WEBHOOK_SECRET and IAC_TOKEN_ENCRYPTION_KEY (iac gen-key)

iac serve
iac analyze ./tests/fixtures/sample-stack
```

Webhook: `POST /webhooks/github` (GitHub HMAC). Poll `GET /runs/{run_id}`.

## Next steps

Plan generation, apply, and drift verification become additional `GraphStage` implementations that consume `ProjectBlueprint`.
