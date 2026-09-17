from __future__ import annotations

import os
from pathlib import Path

from dotenv import load_dotenv
from openai import AuthenticationError, OpenAI

ROOT = Path(__file__).resolve().parent
load_dotenv(ROOT / ".env", override=True)

key = os.getenv("NEBIUS_API_KEY", "").strip()
base_url = os.getenv("NEBIUS_BASE_URL", "https://api.tokenfactory.nebius.com/v1/").strip()
model = os.getenv("NEBIUS_MODEL_TRIAGE", "nvidia/NVIDIA-Nemotron-3-Nano-30B-A3B").strip()

if not key:
    raise SystemExit("NEBIUS_API_KEY is missing from .env")

print(f"Testing Nebius Token Factory at: {base_url}")
print(f"Testing model: {model}")
print(f"API key loaded: yes (length {len(key)}; secret not displayed)")

client = OpenAI(api_key=key, base_url=base_url)

try:
    models = client.models.list()
    ids = [getattr(m, "id", "") for m in getattr(models, "data", [])]
    print(f"Model-list authentication: OK ({len(ids)} models visible)")

    response = client.chat.completions.create(
        model=model,
        messages=[{"role": "user", "content": "Reply with exactly: RESOURCE_SHIELD_OK"}],
        temperature=0,
        max_tokens=128,
        extra_body={"chat_template_kwargs": {"enable_thinking": False}},
    )
    choice = response.choices[0]
    text = (choice.message.content or "").strip()
    print("Chat-completion authentication: OK")
    print(f"Finish reason: {choice.finish_reason}")
    print(f"Provider reply: {text or '[empty]'}")
    if text != "RESOURCE_SHIELD_OK":
        print("Warning: authentication works, but the provider did not return the exact expected test string.")
        raise SystemExit(4)
except AuthenticationError as exc:
    print("Chat/provider authentication failed with HTTP 401.")
    print("The key reached Nebius, but inference authentication was rejected.")
    print("Create a fresh Token Factory API key in the same project, replace NEBIUS_API_KEY in .env, and retry.")
    print(f"Provider message: {exc}")
    raise SystemExit(2)
except SystemExit:
    raise
except Exception as exc:
    print(f"Provider check failed: {type(exc).__name__}: {exc}")
    raise SystemExit(3)
