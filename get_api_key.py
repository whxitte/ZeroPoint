"""
ZeroPoint :: get_api_key.py
============================
Utility to retrieve, rotate, or create your ZeroPoint API key.

Run this once before using the API server.

Usage:
    python3 get_api_key.py              # show current key or create one
    python3 get_api_key.py --rotate     # generate and save a new key
"""

from __future__ import annotations

import argparse
import asyncio
import os
import sys

from loguru import logger

import db.mongo as mongo_ops
from api.auth import generate_api_key, hash_api_key


async def main(rotate: bool = False) -> None:
    logger.remove()
    logger.add(sys.stderr, level="WARNING")  # suppress noise, we print directly

    await mongo_ops.ensure_indexes()
    db = mongo_ops.get_db()

    doc = await db["tenants"].find_one({"tenant_id": "default"})

    if not doc:
        # First time — create the tenant
        raw_key = os.environ.get("ZEROPOINT_API_KEY") or generate_api_key()
        await db["tenants"].insert_one({
            "tenant_id":    "default",
            "name":         "Default (Personal)",
            "api_key_hash": hash_api_key(raw_key),
            "is_active":    True,
            "plan":         "personal",
        })
        _print_key(raw_key, created=True)

    elif rotate:
        # Rotate — generate a new key and update
        raw_key = generate_api_key()
        await db["tenants"].update_one(
            {"tenant_id": "default"},
            {"$set": {"api_key_hash": hash_api_key(raw_key)}},
        )
        _print_key(raw_key, rotated=True)

    else:
        # Key exists — check if env var is set and usable
        env_key = os.environ.get("ZEROPOINT_API_KEY")
        if env_key:
            _print_key(env_key, from_env=True)
        else:
            print("\n" + "=" * 62)
            print("  ZeroPoint API Key")
            print("=" * 62)
            print("  Your API key is stored HASHED in MongoDB — it cannot")
            print("  be retrieved once set. Options:")
            print()
            print("  1. Check your .env for ZEROPOINT_API_KEY=zp_...")
            print("  2. Run with --rotate to generate a new key:")
            print("     python3 get_api_key.py --rotate")
            print("=" * 62 + "\n")

    await mongo_ops.close_connection()


def _print_key(key: str, created: bool = False, rotated: bool = False, from_env: bool = False) -> None:
    label = "Created" if created else ("Rotated" if rotated else "Current")
    print("\n" + "=" * 62)
    print(f"  ZeroPoint API Key — {label}")
    print("=" * 62)
    print(f"  API Key:  {key}")
    print()
    print("  Add to your .env:")
    print(f"  ZEROPOINT_API_KEY={key}")
    print()
    print("  Use in API requests:")
    print(f"  X-API-Key: {key}")
    print()
    print("  Or get a JWT token:")
    print('  curl -X POST http://localhost:8000/api/v1/auth/token \\')
    print('    -H "Content-Type: application/json" \\')
    print('    -d \'{"tenant_id": "default", "api_key": "' + key + '"}\'')
    print("=" * 62 + "\n")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="ZeroPoint API key manager")
    parser.add_argument(
        "--rotate", action="store_true", default=False,
        help="Generate a new API key (invalidates the old one)",
    )
    args = parser.parse_args()
    asyncio.run(main(rotate=args.rotate))