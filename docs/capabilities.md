# Capabilities

A capability is an explicit grant for one exact action name for one agent.

| Effect | Meaning |
|---|---|
| `allow` | executes if all constraints hold |
| `escalate` | if all constraints hold, waits for a designated approver |
| `deny` | always denied (`EXPLICITLY_DENIED`); documents intent |
| *(absent)* | denied (`TOOL_NOT_ALLOWED`) |

Action names are lowercase dotted identifiers (`web.search`, `crm.contact.update`).
There are no wildcards.

## Constraints

| Constraint | Checks | Reason code |
|---|---|---|
| `allowed_arguments: [..]` | no argument outside the list | `ARGUMENT_NOT_ALLOWED` |
| `required_arguments: [..]` | listed arguments present | `ARGUMENT_MISSING` |
| `max_argument_length: N` | no string value (at any depth) longer than N | `ARGUMENT_NOT_ALLOWED` |
| `url_argument: name` | which argument holds a URL (default `url`) | — |
| `allowed_domains: [..]` | URL host equals or is a subdomain of one | `DOMAIN_NOT_ALLOWED` |
| `blocked_domains: [..]` | URL host is not one, nor a subdomain | `DOMAIN_NOT_ALLOWED` |
| `block_private_hosts: true` | not loopback/private/link-local IP, `localhost`, single-label, `.internal`/`.local`/… | `DOMAIN_NOT_ALLOWED` |
| `allowed_targets: [..]` | `to` argument is one of these agents | `TARGET_NOT_ALLOWED` |
| `allowed_actions: [..]` | `action` argument is one of these | `DELEGATED_ACTION_NOT_ALLOWED` |
| `max_calls: N` | at most N allowed invocations by this agent | `BUDGET_EXHAUSTED` |

Any URL constraint also requires the URL to be `http(s)` with a host.

## Harness-owned actions

| Action | Required constraints | Arguments |
|---|---|---|
| `agent.message` | `allowed_targets` | `to`, `body` |
| `agent.delegate` | `allowed_targets`, `allowed_actions` | `to`, `action`, `arguments` |

These cannot be registered as tools. Messaging or delegating to yourself, or to
an unregistered agent, is denied.

## Reason codes

Allow: `CAPABILITY_GRANTED`, `APPROVED_BY_HUMAN`.
Escalate: `REQUIRES_APPROVAL`.
Deny: `MALFORMED_REQUEST`, `UNAUTHENTICATED`, `IDENTITY_MISMATCH`, `UNKNOWN_AGENT`,
`CONTRACT_MISMATCH`, `CONTRACT_EXPIRED`, `RESERVED_ACTION`, `TOOL_NOT_ALLOWED`,
`EXPLICITLY_DENIED`, `CAPABILITY_EXPIRED`, `BUDGET_EXHAUSTED`, `ARGUMENT_NOT_ALLOWED`,
`ARGUMENT_MISSING`, `DOMAIN_NOT_ALLOWED`, `TARGET_NOT_ALLOWED`,
`DELEGATED_ACTION_NOT_ALLOWED`, `APPROVAL_REJECTED`.

Executor refusals (audited as `execution_refused`): `NO_GRANT`, `SIMULATION_MODE`,
`INVALID_GRANT_SIGNATURE`, `GRANT_REQUEST_MISMATCH`, `GRANT_ARGUMENTS_MISMATCH`,
`GRANT_EXPIRED`, `GRANT_ALREADY_USED`, `NO_TOOL_REGISTERED`, `MALFORMED_GRANT`.
