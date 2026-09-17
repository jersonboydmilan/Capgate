## What and why

<!-- What does this change, and why? Link any issue. -->

## Boundary invariants

Capgate's five invariants are in [DESIGN.md](../DESIGN.md). Tick honestly:

- [ ] This change does **not** weaken any of the five invariants — or, if it does, the justification is written below and called out for review.
- [ ] New behaviour an agent can reach is covered by an **adversarial** test (`tests/adversarial/` or `tests/bypass/`), not only a happy-path one.
- [ ] Docs / threat model updated if the security surface changed.

<!-- If an invariant is affected, explain here: -->

## Tests

- [ ] `pytest` passes locally (runs on both `stdlib` and `uvicorn` transports).
- [ ] `pytest -m docker` still passes if the deployment or boundary changed.

## Notes for reviewers

<!-- Anything you want a reviewer to look at closely. -->
