import json
import re
import unittest
from pathlib import Path
from types import SimpleNamespace

from services.handoff_service import HandoffService


class FakeConversations:
    def __init__(self):
        self.prompt = ""

    def create(self, items):
        self.prompt = items[0]["content"]
        return SimpleNamespace(id="conversation-id")


class FakeResponses:
    def __init__(self, domain):
        self.domain = domain

    def create(self, **_kwargs):
        return SimpleNamespace(
            output_text=json.dumps(
                {
                    "domain": self.domain,
                    "is_domain_change": False,
                    "confidence": 0.95,
                    "reasoning": "Matched the active room-painting task",
                }
            )
        )


class FakeClient:
    def __init__(self, domain):
        self.conversations = FakeConversations()
        self.responses = FakeResponses(domain)


class HandoffServiceTests(unittest.TestCase):
    def test_prompt_contains_no_handlebars_expressions(self):
        prompt_path = Path(__file__).parent / "prompts" / "HandoffAgentPrompt.txt"
        prompt = prompt_path.read_text(encoding="utf-8")

        self.assertIsNone(re.search(r"\{\{|\}\}|\{[a-zA-Z_]+\}", prompt))

    def test_first_message_is_classified(self):
        client = FakeClient("interior_designer")
        service = HandoffService(client, "model")

        result = service.classify_intent(
            "I want to paint my living room", "session", "(none)"
        )

        self.assertEqual("interior_designer", result["domain"])
        self.assertTrue(result["is_domain_change"])
        self.assertIn("I want to paint my living room", client.conversations.prompt)

    def test_follow_up_includes_conversation_history(self):
        client = FakeClient("interior_designer")
        service = HandoffService(client, "model")
        service.set_domain("session", "cora")
        history = "user: I want lavender paint for my living room"

        result = service.classify_intent(
            "How much do I need for 25m2?", "session", history
        )

        self.assertEqual("interior_designer", result["domain"])
        self.assertTrue(result["is_domain_change"])
        self.assertIn(history, client.conversations.prompt)
        self.assertIn("How much do I need for 25m2?", client.conversations.prompt)


if __name__ == "__main__":
    unittest.main()