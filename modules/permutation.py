"""
ZeroPoint :: modules/permutation.py
======================================
Subdomain Permutation Engine — active discovery via wordlist mutation.

FIX vs previous version:
  - _resolve_with_massdns() now captures stdout directly instead of using
    -w output_path. The -w flag is silently ignored by massdns in many builds
    when -o S is also specified, leaving the output file empty (0 resolved).
    Capturing stdout is simpler and works across all massdns versions.
  - Replaced --rate-limit with -s (universally supported across all versions)
  - Removed --flush flag (caused issues on some builds)
  - Added stderr logging for massdns 
  
change
This is Module 1b, extending the passive recon from Module 1.
While Subfinder/crt.sh/Shodan find *known* subdomains, permutation
actively generates and resolves *plausible* ones that have never been
publicly indexed or reported.

Strategy: Two-phase approach
  Phase 1 — dnsgen:
    Takes existing subdomains as seeds and generates mutations:
      api.example.com → api2, api-dev, api-staging, api-v2, dev-api, ...
    Uses a built-in wordlist + learned patterns from the seed list.

  Phase 2 — massdns:
    Resolves all generated candidates at ~10,000 DNS queries/second
    using public resolvers. Only domains that actually resolve are kept.

Why this matters:
  Passive recon typically finds 60-80% of subdomains.
  Permutation regularly finds another 10-30%:
    - dev/staging/test environments not in CT logs
    - Internal tools with predictable naming patterns
    - Recently spun-up infrastructure not yet indexed

Requirements:
  pip install dnsgen
  go install github.com/blechschmidt/massdns/cmd/massdns@latest
  # Also needs a resolvers list — auto-downloaded if not present

Usage:
  worker = PermutationWorker()
  async for domain in worker.permute(seeds, root_domain):
      await db.upsert_asset(domain, program_id, ReconSource.PERMUTATION)
"""

from __future__ import annotations

import asyncio
import os
import re
import shutil
import tempfile
from pathlib import Path
from typing import AsyncIterator, List, Optional, Set

import aiohttp
from loguru import logger


# ─────────────────────────────────────────────────────────────────────────────
# Public resolver list — downloaded once, cached locally
# ─────────────────────────────────────────────────────────────────────────────

RESOLVERS_URL     = "https://raw.githubusercontent.com/trickest/resolvers/main/resolvers.txt"
RESOLVERS_DEFAULT = os.path.expanduser("~/.config/zeropoint/resolvers.txt")
# Fallback inline list — used if download fails
FALLBACK_RESOLVERS = [
    "1.1.1.1", "1.0.0.1",           # Cloudflare
    "8.8.8.8", "8.8.4.4",           # Google
    "9.9.9.9", "149.112.112.112",   # Quad9
    "208.67.222.222", "208.67.220.220",  # OpenDNS
    "64.6.64.6", "64.6.65.6",       # Verisign
    "185.228.168.9", "185.228.169.9",   # CleanBrowsing
    "76.76.19.19", "76.223.122.150",    # Alternate DNS
    "94.140.14.14", "94.140.15.15",     # AdGuard
]


async def _ensure_resolvers(resolvers_path: str) -> str:
    """
    Download a curated public DNS resolver list if not already cached.
    Falls back to a hardcoded minimal list if the download fails.
    Returns path to a valid resolvers file.
    """
    rpath = Path(resolvers_path)
    rpath.parent.mkdir(parents=True, exist_ok=True)

    if rpath.exists():
        import time
        age_days = (time.time() - rpath.stat().st_mtime) / 86400
        if age_days < 7:
            logger.debug(f"[permutation] Using cached resolvers: {resolvers_path}")
            return resolvers_path

    logger.info("[permutation] Downloading fresh DNS resolver list...")
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(
                RESOLVERS_URL,
                timeout=aiohttp.ClientTimeout(total=20),
            ) as resp:
                if resp.status == 200:
                    content = await resp.text()
                    ips = [
                        line.strip() for line in content.splitlines()
                        if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", line.strip())
                    ]
                    if len(ips) >= 50:
                        rpath.write_text("\n".join(ips))
                        logger.success(f"[permutation] Downloaded {len(ips)} resolvers → {resolvers_path}")
                        return resolvers_path
    except Exception as exc:
        logger.warning(f"[permutation] Resolver download failed: {exc}")

    rpath.write_text("\n".join(FALLBACK_RESOLVERS))
    logger.warning(f"[permutation] Using fallback {len(FALLBACK_RESOLVERS)}-resolver list.")
    return resolvers_path


# ─────────────────────────────────────────────────────────────────────────────
# dnsgen — generate permutations from seed list
# ─────────────────────────────────────────────────────────────────────────────

def _generate_with_dnsgen(
    seeds:       List[str],
    root_domain: str,
    wordlist:    Optional[str] = None,
) -> List[str]:
    try:
        import dnsgen
    except ImportError:
        logger.error(
            "[permutation] dnsgen not installed.\n"
            "  Fix: pip install dnsgen"
        )
        return []

    candidates: Set[str] = set()
    try:
        if wordlist and os.path.isfile(wordlist):
            generated = list(dnsgen.generate(seeds, wordlist=wordlist))
        else:
            generated = list(dnsgen.generate(seeds))

        for fqdn in generated:
            fqdn = fqdn.lower().strip().rstrip(".")
            if not fqdn:
                continue
            if fqdn.endswith(f".{root_domain}") or fqdn == root_domain:
                candidates.add(fqdn)
    except Exception as exc:
        logger.error(f"[permutation] dnsgen error: {exc}")

    logger.info(f"[permutation] dnsgen generated {len(candidates)} candidate permutations")
    return sorted(candidates)


# ─────────────────────────────────────────────────────────────────────────────
# massdns — mass-resolve candidates via STDOUT (not -w file)
# ─────────────────────────────────────────────────────────────────────────────

async def _resolve_with_massdns(
    candidates:     List[str],
    resolvers_path: str,
    massdns_binary: str = "massdns",
    rate:           int = 5000,
    root_domain:    str = "",
) -> Set[str]:
    """
    Resolve a list of candidate FQDNs using massdns.

    KEY FIX: We capture stdout directly instead of using -w output_path.
    The -w flag is silently ignored in many massdns builds when combined
    with -o S, leaving the output file empty. Stdout capture is reliable
    across all massdns versions.

    massdns -o S outputs lines like:
      api.example.com. A 1.2.3.4
      test.example.com. A 5.6.7.8

    NXDOMAIN entries are filtered by checking parts[1] == "A".
    """
    if not candidates:
        return set()

    if not shutil.which(massdns_binary):
        logger.error(
            f"[permutation] massdns not found at '{massdns_binary}'.\n"
            "  Install: go install github.com/blechschmidt/massdns/cmd/massdns@latest\n"
            "  Or:      sudo apt install massdns"
        )
        return set()

    resolved: Set[str] = set()

    # Write candidates to temp file (with trailing dots for proper FQDN resolution)
    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".txt", prefix="zp_massdns_in_",
        delete=False, encoding="utf-8",
    ) as inf:
        # Add trailing dot to each candidate — massdns expects FQDNs
        inf.write("\n".join(c + "." if not c.endswith(".") else c for c in candidates))
        input_path = inf.name

    cmd = [
        massdns_binary,
        "-r", resolvers_path,
        "-t", "A",              # only A records (IPv4)
        "-o", "S",              # simple output: name A ip  (to stdout)
        "-s", str(rate),        # queries per second (-s works across all versions)
        input_path,
        # NOTE: NO -w flag — stdout capture is more reliable
    ]

    logger.info(
        f"[permutation] massdns resolving {len(candidates)} candidates "
        f"at {rate} qps..."
    )
    logger.debug(f"[permutation] CMD: {' '.join(cmd)}")

    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,  # capture stdout directly
            stderr=asyncio.subprocess.PIPE,  # capture stderr for diagnostics
        )

        # Wait up to 10 minutes for massdns to complete
        stdout_bytes, stderr_bytes = await asyncio.wait_for(
            proc.communicate(), timeout=600
        )

        # Log stderr summary (massdns prints stats to stderr)
        stderr_text = stderr_bytes.decode(errors="replace").strip()
        if stderr_text:
            # Print the last few lines (stats summary)
            stderr_tail = "\n".join(stderr_text.splitlines()[-8:])
            logger.debug(f"[permutation] massdns stats:\n{stderr_tail}")

        # Parse stdout: "sub.example.com. A 1.2.3.4"
        stdout_text = stdout_bytes.decode(errors="replace")
        for line in stdout_text.splitlines():
            line = line.strip()
            if not line:
                continue
            parts = line.split()
            # Format: name type value  (only keep A records)
            if len(parts) >= 3 and parts[1] == "A":
                fqdn = parts[0].rstrip(".").lower()
                # Scope check
                if root_domain and not (
                    fqdn == root_domain or fqdn.endswith(f".{root_domain}")
                ):
                    continue
                resolved.add(fqdn)

        if proc.returncode not in (0, None):
            logger.warning(f"[permutation] massdns exit code: {proc.returncode}")

        logger.success(
            f"[permutation] massdns resolved {len(resolved)} / "
            f"{len(candidates)} candidates"
        )

    except asyncio.TimeoutError:
        logger.warning("[permutation] massdns timed out after 600s")
        try:
            proc.kill()
        except Exception:
            pass
    except FileNotFoundError:
        logger.error(f"[permutation] massdns binary not found at '{massdns_binary}'")
    except Exception as exc:
        logger.exception(f"[permutation] massdns error: {exc}")
    finally:
        try:
            os.unlink(input_path)
        except OSError:
            pass

    return resolved


# ─────────────────────────────────────────────────────────────────────────────
# PermutationWorker — public interface
# ─────────────────────────────────────────────────────────────────────────────

class PermutationWorker:
    """
    Two-phase subdomain permutation engine.

    Phase 1 — dnsgen:  generate mutations from known subdomains
    Phase 2 — massdns: mass-resolve candidates (stdout capture, not -w file)
    """

    def __init__(
        self,
        massdns_binary: str  = "massdns",
        resolvers_path: str  = RESOLVERS_DEFAULT,
        massdns_rate:   int  = 5000,
        wordlist:       str  = "",
        max_candidates: int  = 500_000,
    ) -> None:
        self.massdns_binary = massdns_binary
        self.resolvers_path = resolvers_path
        self.massdns_rate   = massdns_rate
        self.wordlist       = wordlist
        self.max_candidates = max_candidates

    async def permute(
        self,
        seeds:       List[str],
        root_domain: str,
    ) -> AsyncIterator[str]:
        if not seeds:
            logger.warning("[permutation] No seeds provided — skipping")
            return

        seeds_clean = [
            s.lower().strip().rstrip(".")
            for s in seeds if s.strip()
        ]
        seeds_set = set(seeds_clean)

        logger.info(
            f"[permutation] Starting | seeds={len(seeds_clean)} | "
            f"root={root_domain} | max_candidates={self.max_candidates}"
        )

        # Phase 1: generate with dnsgen
        candidates = _generate_with_dnsgen(
            seeds_clean, root_domain, self.wordlist or None
        )
        if not candidates:
            logger.warning("[permutation] dnsgen produced 0 candidates")
            return

        if len(candidates) > self.max_candidates:
            logger.warning(
                f"[permutation] Capping {len(candidates)} → {self.max_candidates} candidates"
            )
            candidates = candidates[: self.max_candidates]

        # Ensure resolvers are available
        resolvers = await _ensure_resolvers(self.resolvers_path)

        # Phase 2: resolve with massdns (stdout capture)
        resolved = await _resolve_with_massdns(
            candidates     = candidates,
            resolvers_path = resolvers,
            massdns_binary = self.massdns_binary,
            rate           = self.massdns_rate,
            root_domain    = root_domain,
        )

        # Yield only genuinely new domains
        new_count = 0
        for domain in sorted(resolved):
            if domain not in seeds_set:
                new_count += 1
                yield domain

        logger.success(
            f"[permutation] Complete | "
            f"candidates={len(candidates)} → resolved={len(resolved)} → "
            f"new={new_count}"
        )