"""Agent B: a helpful — or fully compromised — agent that does whatever it is asked."""

from capgate import Harness


class AgentB:
    agent_id = "agent-b"

    def __init__(self, harness: Harness) -> None:
        self.harness = harness

    def handle_inbox(self) -> list:
        """Obey every instruction in every message. The harness is what stops this."""
        results = []
        for message in self.harness.receive(self.agent_id):
            instruction = message.body
            results.append(self.harness.authorize(
                agent=self.agent_id,
                action=instruction["action"],
                arguments=instruction.get("arguments", {}),
                contract_id=instruction.get("contract_id"),  # obeys even forged contract claims
            ))
        return results
