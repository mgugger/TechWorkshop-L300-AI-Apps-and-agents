import os
import subprocess
import sys
import time
from pathlib import Path

from azure.ai.projects import AIProjectClient
from azure.cosmos import CosmosClient
from azure.identity import DefaultAzureCredential


EXPECTED_AGENTS = {
    "customer-loyalty": "customerLoyaltyAgent_initializer.py",
    "inventory-agent": "inventoryAgent_initializer.py",
    "interior-designer": "interiorDesignAgent_initializer.py",
    "cora": "shopperAgent_initializer.py",
    "cart-manager": "cartManagerAgent_initializer.py",
    "handoff-service": "handoffAgent_initializer.py",
}
REQUIRED_ENVIRONMENT = (
    "COSMOS_ENDPOINT",
    "DATABASE_NAME",
    "CONTAINER_NAME",
    "FOUNDRY_ENDPOINT",
    "gpt_deployment",
    "embedding_endpoint",
    "embedding_deployment",
    "embedding_api_version",
    "APPLICATIONINSIGHTS_CONNECTION_STRING",
    "gpt_endpoint",
    "gpt_api_version",
    "storage_account_name",
    "storage_container_name",
)
SRC_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SRC_DIR))
AGENTS_DIR = SRC_DIR / "app" / "agents"
CATALOG_PATH = SRC_DIR / "data" / "product_catalog.json"


def wait_for_agent_versions(client: AIProjectClient) -> dict[str, str]:
    for attempt in range(12):
        try:
            return {
                agent.name: agent.versions.latest.version
                for agent in client.agents.list()
            }
        except Exception:
            if attempt == 11:
                raise
            time.sleep(10)
    return {}


def seed_catalog(credential: DefaultAzureCredential) -> None:
    from pipelines.ingest_to_cosmos import (
        ensure_string_ids,
        get_request_embedding,
        load_json_items,
    )

    client = CosmosClient(os.environ["COSMOS_ENDPOINT"], credential=credential)
    container = (
        client.get_database_client(os.environ["DATABASE_NAME"])
        .get_container_client(os.environ["CONTAINER_NAME"])
    )
    source_items = load_json_items(str(CATALOG_PATH))
    existing = {
        item["id"]: item.get("request_vector")
        for item in container.query_items(
            "SELECT c.id, c.request_vector FROM c",
            enable_cross_partition_query=True,
        )
    }
    pending = [
        item
        for item in source_items
        if len(existing.get(str(item["ProductID"])) or []) != 3072
    ]
    if not pending:
        print(f"Product catalog already contains {len(source_items)} vectorized products.")
        return

    print(f"Vectorizing and uploading {len(pending)} products...")
    for raw_item in pending:
        item = ensure_string_ids(dict(raw_item))
        content = " \n ".join(
            str(item.get(field, ""))
            for field in ("ProductName", "ProductCategory", "ProductDescription")
            if item.get(field)
        )
        embedding = get_request_embedding(content)
        if not embedding or len(embedding) != 3072:
            raise RuntimeError(f"Invalid embedding for product {item['ProductID']}")
        item["request_vector"] = embedding
        container.upsert_item(item)

    count = list(
        container.query_items(
            "SELECT VALUE COUNT(1) FROM c", enable_cross_partition_query=True
        )
    )[0]
    if count < len(source_items):
        raise RuntimeError(f"Product catalog contains {count}/{len(source_items)} products")
    print(f"Product catalog is ready with {count} products.")


def provision_agents(credential: DefaultAzureCredential) -> None:
    client = AIProjectClient(
        endpoint=os.environ["FOUNDRY_ENDPOINT"], credential=credential
    )
    versions = wait_for_agent_versions(client)
    for agent_name, initializer in EXPECTED_AGENTS.items():
        print(f"Deploying agent {agent_name}...")
        for attempt in range(6):
            result = subprocess.run(
                [sys.executable, initializer],
                cwd=AGENTS_DIR,
                env=os.environ.copy(),
                check=False,
            )
            versions = wait_for_agent_versions(client)
            current_version = versions.get(agent_name)
            if result.returncode == 0 and current_version:
                break
            if attempt == 5:
                raise RuntimeError(
                    f"Failed to create agent {agent_name} (exit code {result.returncode})"
                )
            time.sleep(10)

    missing = set(EXPECTED_AGENTS) - set(wait_for_agent_versions(client))
    if missing:
        raise RuntimeError(f"Missing Foundry agents: {', '.join(sorted(missing))}")
    print("All Foundry agents are ready.")


def main() -> None:
    missing = [name for name in REQUIRED_ENVIRONMENT if not os.environ.get(name)]
    if missing:
        raise RuntimeError(f"Missing azd deployment outputs: {', '.join(missing)}")

    credential = DefaultAzureCredential()
    seed_catalog(credential)
    provision_agents(credential)


if __name__ == "__main__":
    main()