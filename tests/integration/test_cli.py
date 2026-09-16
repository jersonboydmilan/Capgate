import json
from pathlib import Path

from harness.cli import main

ROOT = Path(__file__).resolve().parents[2]


def test_simulate_readme_demo(capsys):
    assert main(["simulate", str(ROOT / "examples/simulation/task.yaml")]) == 0
    out = capsys.readouterr().out
    assert "AGENT HARNESS — SIMULATION" in out
    for line in ["01  web.search", "03  database.read", "04  agent.delegate"]:
        assert line in out
    assert "Allowed:      3" in out and "Denied:       1" in out and "Escalated:    1" in out
    assert "No external actions were executed." in out


def test_simulate_and_enforce_make_identical_decisions(tmp_path, capsys):
    task = ROOT / "examples/simulation/task.yaml"
    main(["simulate", str(task), "--json"])
    simulated = json.loads(capsys.readouterr().out)
    main(["enforce", str(task), "--json", "--audit", str(tmp_path / "a.jsonl")])
    enforced = json.loads(capsys.readouterr().out)
    strip = lambda rows: [(r["label"], r["decision"], r["reason"]) for r in rows]
    assert strip(simulated["rows"]) == strip(enforced["rows"])
    assert {r["outcome"] for r in simulated["rows"]} == {"not executed"}


def test_enforce_executes_and_audit_cli_reads_trail(tmp_path, capsys):
    audit = tmp_path / "audit.jsonl"
    assert main(["enforce", str(ROOT / "examples/basic/task.yaml"), "--audit", str(audit)]) == 0
    out = capsys.readouterr().out
    assert "succeeded" in out and "blocked" in out

    assert main(["audit", str(audit), "--verify"]) == 0
    assert "hash chain intact" in capsys.readouterr().out
    assert main(["audit", str(audit), "--decision", "deny"]) == 0
    table = capsys.readouterr().out
    assert "DENY" not in table and "deny" in table and "allow " not in table


def test_fail_on_flag(capsys):
    assert main(["simulate", str(ROOT / "examples/simulation/task.yaml"), "--fail-on", "deny"]) == 1


def test_validate_rejects_bad_contract(tmp_path, capsys):
    bad = tmp_path / "bad.yaml"
    bad.write_text("contract_id: x\ngoal: g\nmax_steps: 50\nagent: a\nallowed_tools: [web.search]\nmax_step: 3\n")
    assert main(["validate", str(bad)]) == 2
    assert "unknown contract fields" in capsys.readouterr().err
