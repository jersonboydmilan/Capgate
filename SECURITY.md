# Security policy

Agent Harness is a runtime **authority boundary** for autonomous agents: the
agent proposes, the harness authorizes, the executor acts. Its whole purpose is
to hold under a hostile agent, so security reports are the most valuable
contribution you can make.

## The claim we are asking you to break

With the reference deployment in [`deploy/`](deploy/README.md) — or any
deployment that reproduces its properties — a fully compromised agent that
ignores the SDK should not be able to:

1. cause any consequential action (tool call or inter-agent message) that its
   own contract does not grant;
2. obtain another agent's authority by delegating, messaging, impersonating, or
   claiming a different contract;
3. reach a tool, another agent, secret material, or the network by any route
   other than the harness API;
4. forge, replay, extend, or otherwise misuse a credential or an execution permit;
5. execute an escalated action without a designated human approval;
6. erase or rewrite the audit trail undetectably;
7. exhaust or reset budgets, or take the harness itself down, from within its
   allotted request budget.

The [threat model](docs/threat-model.md) states precisely what is and is not
claimed, including what is out of scope (kernel/runtime escape, a compromised
Docker host, harness API bugs are in scope).

If you find a way to do any of the above — or anything else that lets an agent
act outside its contract — we want to know.

## Reporting a vulnerability

- **Preferred:** open a private report via GitHub Security Advisories
  ("Report a vulnerability" on the Security tab).
- **Otherwise:** email the maintainers (see the repository's project metadata).
  Encrypt if you can.

Please include a proof of concept where possible — ideally as a failing test in
the style of `tests/adversarial/` or `tests/bypass/`, which makes triage and a
regression test immediate.

We aim to acknowledge within 3 business days. Because there is no packaged
release yet, coordinated disclosure is informal: we will agree a timeline with
you, fix on a branch, and credit you in the advisory and changelog unless you
prefer otherwise.

## Scope

In scope: everything under `src/harness/`, the reference deployment in
`deploy/`, and the documented API. A finding that only affects a cooperative,
in-process integration (an agent sharing the harness's own process) is a
hardening note, not a boundary break — see the threat model on why in-process
use is not a security boundary.
