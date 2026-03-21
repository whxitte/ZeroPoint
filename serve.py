"""
ZeroPoint :: serve.py
======================
Convenience script to launch the REST API server.

Usage:
    python3 serve.py                    # default: 0.0.0.0:8000
    python3 serve.py --port 9000        # custom port
    python3 serve.py --reload           # hot-reload for development

The API server exposes all your ZeroPoint data via REST:
    http://localhost:8000/api/docs      ← Interactive Swagger UI
    http://localhost:8000/api/redoc     ← ReDoc documentation

Authentication:
    All endpoints need an API key or JWT.
    The default tenant's API key is printed on first start.
    Add it to .env as ZEROPOINT_API_KEY=zp_...

Endpoints summary:
    POST  /api/v1/auth/token             — exchange API key for JWT
    GET   /api/v1/programs/              — list programs
    GET   /api/v1/assets/?program_id=X   — list assets
    GET   /api/v1/findings/?program_id=X — list Nuclei findings
    GET   /api/v1/leaks/?program_id=X    — list GitHub OSINT leaks
    GET   /api/v1/health                 — health check + DB status
"""

from __future__ import annotations

import argparse
import sys

import uvicorn
from loguru import logger


def main() -> None:
    parser = argparse.ArgumentParser(
        description="ZeroPoint API Server",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 serve.py                     # production mode
  python3 serve.py --reload            # development mode (auto-restart on changes)
  python3 serve.py --port 9000         # custom port
  python3 serve.py --host 127.0.0.1   # localhost only (more secure)
        """,
    )
    parser.add_argument("--host",   type=str, default="0.0.0.0",   help="Bind host (default: 0.0.0.0)")
    parser.add_argument("--port",   type=int, default=8000,         help="Bind port (default: 8000)")
    parser.add_argument("--reload", action="store_true", default=False, help="Enable hot-reload (dev mode)")
    parser.add_argument("--workers",type=int, default=1,            help="Worker processes (default: 1, use 1 with Motor)")
    args = parser.parse_args()

    logger.info("=" * 60)
    logger.info("  ZeroPoint API Server")
    logger.info("=" * 60)
    logger.info(f"  Host:    {args.host}")
    logger.info(f"  Port:    {args.port}")
    logger.info(f"  Reload:  {args.reload}")
    logger.info(f"  Docs:    http://{args.host if args.host != '0.0.0.0' else 'localhost'}:{args.port}/api/docs")
    logger.info("=" * 60)

    # Motor (async MongoDB) requires a single process — multiple workers
    # would each get their own event loop + connection pool which is correct,
    # but warn the user since it changes behaviour.
    if args.workers > 1:
        logger.warning(
            f"Running with {args.workers} workers. Each worker has its own "
            "Motor connection pool — this is correct but increases DB connections."
        )

    uvicorn.run(
        "api.main:app",
        host    = args.host,
        port    = args.port,
        reload  = args.reload,
        workers = args.workers if not args.reload else 1,  # reload requires 1 worker
        log_level = "info",
    )


if __name__ == "__main__":
    main()