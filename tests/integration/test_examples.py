import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def run(path, cwd=None):
    proc = subprocess.run([sys.executable, str(path)], cwd=cwd, capture_output=True, text=True, timeout=60)
    assert proc.returncode == 0, proc.stderr
    return proc.stdout


def test_delegation_boundary_demo():
    out = run(ROOT / "examples/delegation-boundary/agent_a.py", cwd=ROOT / "examples/delegation-boundary")
    assert "Rows written to the database: 0" in out
    assert "agent-b  contract-b  deny  TOOL_NOT_ALLOWED     delegated_by=agent-a" in out


def test_basic_example():
    out = run(ROOT / "examples/basic/run.py")
    assert "executor refused: NO_GRANT" in out and "chain intact: True" in out


def test_adversarial_agent_example():
    out = run(ROOT / "examples/adversarial-agent/run.py")
    side_effects = out.split("Side effects recorded by the real tool:")[1].split("Audit trail")[0]
    assert side_effects.strip().splitlines() == ["/web.search  {'query': 'hello'}"]
