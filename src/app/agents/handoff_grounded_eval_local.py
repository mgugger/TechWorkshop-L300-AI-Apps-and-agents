import argparse
import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict

import httpx
from azure.ai.evaluation import evaluate
from azure.identity import DefaultAzureCredential, get_bearer_token_provider
from dotenv import load_dotenv


def _normalize_domain(value: str) -> str:
    text = (value or "").strip().lower()
    if text.startswith("domain:"):
        text = text.split(":", 1)[1].strip()
    return text


def _extract_predicted_domain(response_text: str) -> str:
    """Extract domain from handoff-service JSON output or free text fallback."""
    if not response_text:
        return ""

    # Preferred path: parse JSON payload emitted by handoff-service.
    try:
        payload = json.loads(response_text)
        if isinstance(payload, dict):
            return _normalize_domain(str(payload.get("domain", "")))
    except Exception:
        pass

    # Fallback path for non-JSON responses.
    match = re.search(r"domain\s*[:=]\s*([a-zA-Z_\-]+)", response_text, flags=re.IGNORECASE)
    return _normalize_domain(match.group(1) if match else "")


def build_target(foundry_endpoint: str, model: str):
    credential = DefaultAzureCredential()
    token_provider = get_bearer_token_provider(credential, "https://ai.azure.com/.default")
    endpoint = foundry_endpoint.rstrip("/")

    def target(query: str) -> Dict[str, Any]:
        token = token_provider()
        response = httpx.post(
            f"{endpoint}/openai/v1/responses",
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {token}",
            },
            json={
                "model": model,
                "input": query,
                "agent_reference": {"name": "handoff-service", "type": "agent_reference"},
            },
            timeout=180,
        )
        response.raise_for_status()
        body = response.json()

        output_text = body.get("output_text", "")
        if not output_text:
            for item in body.get("output", []):
                if item.get("type") == "message":
                    for content in item.get("content", []):
                        if content.get("type") == "output_text":
                            output_text = content.get("text", "")
                            break

        return {
            "response": output_text,
            "predicted_domain": _extract_predicted_domain(output_text),
        }

    return target


def routing_accuracy_evaluator(expected_domain: str, predicted_domain: str) -> Dict[str, Any]:
    expected = _normalize_domain(expected_domain)
    predicted = _normalize_domain(predicted_domain)
    is_match = int(expected == predicted and expected != "")

    return {
        "routing_accuracy": is_match,
        "expected_domain": expected,
        "predicted_domain": predicted,
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run local grounded eval for handoff-service using azure-ai-evaluation SDK."
    )
    parser.add_argument(
        "--data",
        default="data/handoff_service_evaluation_grounded.jsonl",
        help="Path to grounded JSONL dataset.",
    )
    parser.add_argument(
        "--output",
        default=None,
        help="Optional output path. Defaults to eval_results/handoff_service_grounded_<timestamp>.json",
    )
    parser.add_argument(
        "--name",
        default="handoff-service-grounded-local",
        help="Evaluation run name.",
    )
    return parser.parse_args()


def main() -> None:
    load_dotenv()
    args = parse_args()

    foundry_endpoint = os.getenv("FOUNDRY_ENDPOINT", "").strip()
    model = os.getenv("gpt_deployment", "").strip()

    if not foundry_endpoint:
        raise ValueError("FOUNDRY_ENDPOINT is required in your environment or .env")
    if not model:
        raise ValueError("gpt_deployment is required in your environment or .env")

    data_path = Path(args.data)
    if not data_path.exists():
        raise FileNotFoundError(f"Dataset not found: {data_path}")

    output_path = args.output
    if not output_path:
        ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%SZ")
        output_dir = Path("eval_results")
        output_dir.mkdir(parents=True, exist_ok=True)
        output_path = str(output_dir / f"handoff_service_grounded_{ts}.json")

    result = evaluate(
        data=str(data_path),
        target=build_target(foundry_endpoint, model),
        evaluators={"routing": routing_accuracy_evaluator},
        evaluator_config={
            "routing": {
                "column_mapping": {
                    "expected_domain": "${data.expected_domain}",
                    "predicted_domain": "${target.predicted_domain}",
                }
            }
        },
        evaluation_name=args.name,
        output_path=output_path,
    )

    print("Evaluation completed.")
    print(f"Rows evaluated: {result.get('rows', 'n/a')}")
    print(f"Output file: {output_path}")
    print("Metrics:")
    print(json.dumps(result.get("metrics", {}), indent=2))


if __name__ == "__main__":
    main()