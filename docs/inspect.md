# capgate inspect

A thin, local inspection UI over the pieces that already exist: the simulation
engine, the audit trail, the approvals API and the policy engine. One Python
process, one HTML page, no build step, no accounts.

```bash
capgate inspect --task examples/simulation/task.yaml --audit audit.jsonl \
                --harness-url http://127.0.0.1:8080 --approver-token-file alice.token
```

Or a self-contained live stack with traffic and pending escalations:

```bash
python examples/inspect/demo.py
```

## Views

| Tab | What it does | Backed by |
|---|---|---|
| **Simulate** | Task steps and contract side by side. Every edit re-runs the simulation (Ctrl/⌘-Enter to force) and shows the allow / deny / escalate table with reason code, the rule that fired and its detail. Selecting a row highlights the grant it hit. Invalid YAML or contracts are reported inline. | `run_task(..., Mode.SIMULATE)`, the same engine as `capgate simulate` and enforcement |
| **Audit** | Loads an audit JSONL file, verifies the hash chain on every load and names the first broken record; rows after a break are marked untrusted. Filter by agent, action, decision, event or decision id; “Show correlated” follows a decision through execution and approval. “live” polls every 3s. | Streaming read of the file; no copy in memory |
| **Escalations** | Pending approvals from a running harness with the proposed action, arguments, contract, reason and delegation chain. Approve or reject with a note; the result (and execution outcome) is shown and the note lands in the audit trail. Refreshes every 5s without disturbing what you are typing. | `GET/POST /v1/approvals` on the harness, with the approver token held by the inspect process |
| **Policy** | Grants per contract and agent; “What would this proposal hit?” evaluates a hypothetical action and shows the decision, rule and capability; “Diff” compares the current contract with an edited one and classifies each grant change as widened, narrowed, added, removed or changed. | Pure `policy.evaluate` with empty budgets (nothing is consumed or recorded) |

## Security model (local tool, but it can approve actions)

- Binds to loopback only; refuses any other address.
- Every API request must carry a per-session nonce embedded in the page. A page
  on another origin cannot read it, and the custom header forces a CORS
  preflight the server never answers — so a malicious website open in the same
  browser cannot trigger approvals (CSRF).
- The `Host` header must name this server, which defeats DNS rebinding.
- The approver token stays in the inspect process; the browser never sees it.
- Content-Security-Policy allows only the page's own nonce-tagged script and
  same-origin requests; all data is inserted as text, never HTML.

Whoever can use your browser session on this machine can approve actions as the
configured approver — treat `capgate inspect` like any local admin console.

## With the Docker deployment

```bash
cd deploy && docker compose up -d harness
docker compose exec harness python3 -m capgate.cli token issue --keyring /secrets/token_keyring \
    --sub alice --role approver --ttl 1h > alice.token
docker compose cp harness:/data/audit.jsonl ./audit.jsonl
capgate inspect --audit audit.jsonl --harness-url http://127.0.0.1:8080 --approver-token-file alice.token
```

`alice` must be an approver in `deploy/config/contracts.yaml`.
