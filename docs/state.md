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
- **Shared rate limits.** Set `rate_limit.shared: true` and the token buckets
  live in the state store, so per-client and per-principal limits (and the
  auth-failure audit sampler) hold across the whole fleet, not per replica.
  On Postgres each bucket is an atomic per-row update (no cluster-wide lock),
  so rate checks stay parallel. Leave it off (default) for a per-replica
  in-process limiter.
- **Shared audit sink.** Point `audit:` (or `audit_env:`) at a `postgresql://`
  URL and every replica appends to one `audit` table under its own
  `stream_id`, each stream its own hash chain. One queryable, tamper-evident
  trail for the fleet, verifiable per stream — with no cross-replica lock,
  since a replica only extends its own stream. A file path still gives the
  per-host JSONL trail.

The docker test `tests/integration/test_state_multihost.py` (`pytest -m docker`)
starts a real Postgres and proves two replicas share one budget exactly and that
a permit minted on one replica is usable once, from any replica.
