# Azure imports
from azure.identity import DefaultAzureCredential
from azure.ai.evaluation.red_team import RedTeam, RiskCategory, AttackStrategy
from pyrit.prompt_target import OpenAIChatTarget
import os
import asyncio
from dotenv import load_dotenv

load_dotenv()

def _normalize_openai_endpoint(raw_endpoint: str) -> str:
    """Return an Azure OpenAI base URL compatible with newer pyrit/OpenAI SDK usage."""
    endpoint = (raw_endpoint or "").strip().rstrip("/")
    if not endpoint:
        raise ValueError("gpt_endpoint environment variable is required")

    # Convert old style URLs (with deployments/chat path) to the new base URL.
    deployments_token = "/openai/deployments/"
    if deployments_token in endpoint:
        endpoint = endpoint.split(deployments_token, 1)[0]

    if endpoint.endswith("/openai"):
        return f"{endpoint}/v1"
    if endpoint.endswith("/openai/v1"):
        return endpoint
    return f"{endpoint}/openai/v1"

# Azure AI Project Information
azure_ai_project = os.getenv("FOUNDRY_ENDPOINT")

# Instantiate your AI Red Teaming Agent
red_team_agent = RedTeam(
    azure_ai_project=azure_ai_project,
    credential=DefaultAzureCredential(),
    custom_attack_seed_prompts="data/custom_attack_prompts.json",
)

chat_target = OpenAIChatTarget(
    model_name=os.environ.get("gpt_deployment"),
    endpoint=_normalize_openai_endpoint(os.environ.get("gpt_endpoint", "")),
    api_key=os.environ.get("gpt_api_key"),
)

async def main():
    red_team_result = await red_team_agent.scan(
        target=chat_target,
        scan_name="Red Team Scan - Easy-Moderate Strategies",
        attack_strategies=[
            AttackStrategy.Flip,
            AttackStrategy.ROT13,
            AttackStrategy.Base64,
            AttackStrategy.AnsiAttack,
            AttackStrategy.Tense
        ])
    
asyncio.run(main())
