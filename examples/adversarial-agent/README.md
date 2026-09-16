# Adversarial agent

`malicious_agent.py` runs as its own OS process, ignores the SDK, and tries
every route around the harness: calling the real tool endpoint directly,
impersonating a privileged agent, claiming another contract, approving its own
escalation, and delegating to a privileged agent.

```bash
python examples/adversarial-agent/run.py
```

The only side effect the real tool records is the one in-contract `web.search`.
The same scenario runs as an automated test in `tests/bypass/`.

What makes this hold is *credential custody*, not the SDK: the tool endpoint
requires a credential that only the executor has, and the agent process is
started without it. See [`docs/threat-model.md`](../../docs/threat-model.md)
for what this does not cover (an agent on the same host with the ability to
read the harness process's memory or files).
