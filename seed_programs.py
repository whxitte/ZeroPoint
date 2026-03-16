"""
ZeroPoint — Program Seeder

Use this script to add/update bug bounty programs in the `programs` collection.
Run this once before starting the ingestor.

Usage:
    python seed_programs.py

Edit the PROGRAMS list below with your actual targets.
"""

from __future__ import annotations

import asyncio
import sys

from loguru import logger

from db.mongo import upsert_program, close_connection, ensure_indexes
from models import ProgramPlatform, Program


# ─────────────────────────────────────────────
# ✏️  EDIT THIS LIST WITH YOUR PROGRAMS
# ─────────────────────────────────────────────

PROGRAMS: list[Program] = [
    Program(
        program_id="shopify_h1",
        name="Shopify",
        platform=ProgramPlatform.HACKERONE,
        domains=["shopify.com", "myshopify.com"],
        wildcards=["*.shopify.com", "*.myshopify.com"],
        is_active=True,
    ),
    Program(
        program_id="gitlab_h1",
        name="GitLab",
        platform=ProgramPlatform.HACKERONE,
        domains=["gitlab.com"],
        wildcards=["*.gitlab.com"],
        is_active=True,
    ),
    # Add more programs here...
]


async def seed() -> None:
    logger.remove()
    logger.add(sys.stderr, level="DEBUG", colorize=True,
               format="<green>{time:HH:mm:ss}</green> | <level>{level}</level> | {message}")

    await ensure_indexes()

    try:
        for program in PROGRAMS:
            await upsert_program(program)
            logger.success(f"Seeded program: {program.name} ({program.program_id})")

        logger.success(f"✓ Seeded {len(PROGRAMS)} program(s) successfully")
    finally:
        await close_connection()


if __name__ == "__main__":
    asyncio.run(seed())
