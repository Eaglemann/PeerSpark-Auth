import httpx
import os
from dotenv import load_dotenv

load_dotenv()


HASURA_URL = os.getenv("HASURA_URL")
HASURA_ADMIN_SECRET = os.getenv("HASURA_ADMIN_SECRET")

headers = {
    "Authorization": f"Bearer {HASURA_ADMIN_SECRET}"
}

async def run_query(query: str, variables: dict = {}):
    async with httpx.AsyncClient as client:
        response = await client.post(
            HASURA_URL,
            json={"query": query, "variables": variables},
            headers=headers
        )
        response.raise_for_status()

    return response.json()