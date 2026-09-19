# Authority state and backends

Capgate keeps the state that must be consistent and durable for the boundary to
hold: per-contract **step budgets** and per-capability **call counts**, **used
execution permits** (single-use), **pending/decided approvals**, undelivered
**inter-agent messages**, and **revoked credentials**.

Pick a backend with a URL (config `state:`, or `state_env:` naming an env var
that holds it — use that for a Postgres DSN so the secret isn't in the file):

| URL | Backend | Scope |
|---|---|---|
| `memory://` (or omit) | in-process | one process; tests, simulation |
| `sqlite:///abs/path` or a bare path | SQLite (WAL) | one host, many processes (file write lock) |
| `postgresql://user:pw@host/db` | PostgreSQL | **many hosts** (shared, transactional) |

```yaml
# server.yaml
state_env: CAPGATE_STATE_DSN         # e.g. postgresql://capgate:…@db:5432/capgate
# or, single host:
# state: /data/state.db
```

Postgres needs the `postgres` extra: `pip install "capgate[postgres]"`.

## The contract every backend keeps

- **`transaction()` makes read-evaluate-increment atomic.** The interceptor
  reads the budget, evaluates policy, and increments the counter inside one
  transaction, so a contract's `max_steps` / a capability's `max_calls` cannot
  be overspent under concurrency.
- **`claim_grant` is single-use.** An execution permit can be redeemed once,
  even if two requests race — the loser is refused `GRANT_ALREADY_USED`.
- **Approvals are taken once and re-checked live.** Approving an escalation
  takes the pending record, re-reads the *current* budget, and records the
  decision in one transaction — so an approval cannot push past a budget that
  was spent after the escalation (on this host or another).

## Multi-host with PostgreSQL

Point every harness replica at the same database:

```
harness A ─┐
harness B ─┼─► PostgreSQL (budgets, permits, approvals, messages, revocations)
harness C ─┘
```

Each `transaction()` holds a **cluster-wide advisory lock**
(`pg_advisory_xact_lock`) for its duration, so the replicas serialize their
state transactions and make the same budget, permit and approval decisions
whichever one serves a request. This favours correctness over throughput (all
state transactions serialize); finer per-contract locking is a later
optimisation — see the roadmap.

Two things to get right across replicas:

- **Share the token signing key** (same `signing_key`/keyring) so an execution
  permit minted on one replica verifies on another.
- **Rate limits are still per replica.** The token-bucket limiter is in-process;
  N replicas allow up to N× the per-principal rate. Put a shared limiter (or a
  fronting proxy's global rate limit) ahead of the fleet if you need a hard
  cluster-wide cap. The audit trail is also per host (append-only JSONL per
  replica); ship them to a common sink to query the fleet as one.

The docker test `tests/integration/test_state_multihost.py` (`pytest -m docker`)
starts a real Postgres and proves two replicas share one budget exactly and that
a permit minted on one replica is usable once, from any replica.
