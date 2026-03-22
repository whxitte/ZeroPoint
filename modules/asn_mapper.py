"""
ZeroPoint :: modules/asn_mapper.py
====================================
ASN Mapper — resolves domains to their company's full IP range.

BGPView (api.bgpview.io) is permanently down as of 2024 (Cloudflare Error 523).
This module uses two reliable, free, auth-free alternatives:

  Phase 1 — IP-based discovery:
    ipinfo.io  → GET /api/{ip}
                 Returns: {"org": "AS13335 Cloudflare, Inc.", ...}
                 Free: 50,000 requests/month, no token required
                 Auth token optional — add IPINFO_TOKEN to .env for higher limits

    RIPE Stat  → GET /data/announced-prefixes/data.json?resource=AS{n}
                 Returns all IPv4/IPv6 CIDR prefixes announced by an ASN
                 Free: unlimited, no auth required

  Phase 2 — Name-based fallback (when all IPs are CDN-owned):
    RIPE Stat  → GET /data/searchcomplete/data.json?term={company}
                 Searches for ASNs matching a company name
                 Filters results to only ASNs whose name contains the keyword

Why two phases:
  GitLab, Shopify, etc. proxy everything through Cloudflare → AS13335.
  The IPs httpx discovers are Cloudflare's — not the target company's.
  Phase 2 searches for "gitlab" in RIPE's ASN registry and finds
  AS58061 (GITLAB-US-EAST-1), AS400800 (GITLAB-US), etc. directly.
"""

from __future__ import annotations

import asyncio
import ipaddress
import re
from typing import Dict, List, Optional, Set, Tuple

import aiohttp
from loguru import logger

from models import ASNInfo


# ─────────────────────────────────────────────────────────────────────────────
# ipinfo.io client — IP → ASN
# ─────────────────────────────────────────────────────────────────────────────

class IPInfoClient:
    """
    Resolves IP addresses to ASN numbers via ipinfo.io.
    Free tier: 50,000 requests/month, no authentication required.
    Optional: set IPINFO_TOKEN in .env for higher limits.
    """

    BASE = "https://ipinfo.io"

    def __init__(self, token: Optional[str] = None, rate_delay: float = 0.5) -> None:
        self.token      = token
        self.rate_delay = rate_delay

    def _headers(self) -> dict:
        h = {"Accept": "application/json", "User-Agent": "ZeroPoint/1.0"}
        if self.token:
            h["Authorization"] = f"Bearer {self.token}"
        return h

    async def ip_to_asn(
        self,
        session: aiohttp.ClientSession,
        ip:      str,
    ) -> Optional[Tuple[int, str]]:
        """
        Resolve an IP address to (asn_number, asn_name).
        ipinfo.io returns: {"org": "AS13335 Cloudflare, Inc."}
        """
        try:
            async with session.get(
                f"{self.BASE}/{ip}/json",
                headers=self._headers(),
                timeout=aiohttp.ClientTimeout(total=10),
            ) as resp:
                if resp.status == 429:
                    logger.warning("[asn] ipinfo.io rate limited — sleeping 60s")
                    await asyncio.sleep(60)
                    return None
                if resp.status != 200:
                    logger.debug(f"[asn] ipinfo.io HTTP {resp.status} for {ip}")
                    return None

                data = await resp.json()
                org  = data.get("org", "")   # e.g. "AS13335 Cloudflare, Inc."
                if not org or not org.startswith("AS"):
                    return None

                # Parse "AS13335 Cloudflare, Inc." → (13335, "Cloudflare, Inc.")
                parts    = org.split(" ", 1)
                asn_num  = int(parts[0][2:])   # strip "AS" prefix
                asn_name = parts[1] if len(parts) > 1 else org
                return asn_num, asn_name

        except asyncio.TimeoutError:
            logger.debug(f"[asn] ipinfo.io timeout for {ip}")
            return None
        except Exception as exc:
            logger.debug(f"[asn] ipinfo.io error for {ip}: {exc}")
            return None


# ─────────────────────────────────────────────────────────────────────────────
# RIPE Stat client — ASN → prefixes, and name search
# ─────────────────────────────────────────────────────────────────────────────

class RIPEStatClient:
    """
    Fetches IP prefix data and searches ASNs by name via the RIPE Stat API.
    Free, unlimited, no authentication required.
    API docs: https://stat.ripe.net/docs/data_api
    """

    BASE = "https://stat.ripe.net/data"

    def __init__(self, rate_delay: float = 1.0) -> None:
        self.rate_delay = rate_delay

    async def asn_prefixes(
        self,
        session:    aiohttp.ClientSession,
        asn_number: int,
    ) -> Tuple[List[str], List[str]]:
        """
        Fetch all IPv4 and IPv6 prefixes announced by an ASN.
        Returns (ipv4_prefixes, ipv6_prefixes).
        """
        try:
            async with session.get(
                f"{self.BASE}/announced-prefixes/data.json",
                params={"resource": f"AS{asn_number}", "starttime": "now"},
                timeout=aiohttp.ClientTimeout(total=20),
            ) as resp:
                if resp.status != 200:
                    return [], []
                data = await resp.json()

                prefixes_raw = (
                    data.get("data", {}).get("prefixes", [])
                )
                ipv4, ipv6 = [], []
                for entry in prefixes_raw:
                    p = entry.get("prefix", "")
                    if not p:
                        continue
                    if ":" in p:
                        ipv6.append(p)
                    else:
                        ipv4.append(p)
                return ipv4, ipv6

        except Exception as exc:
            logger.debug(f"[asn] RIPE asn_prefixes error AS{asn_number}: {exc}")
            return [], []

    async def search_asns_by_name(
        self,
        session: aiohttp.ClientSession,
        query:   str,
    ) -> List[Tuple[int, str]]:
        """
        Search for ASNs matching a company name using RIPE Stat searchcomplete.
        Returns list of (asn_number, asn_name) tuples.

        Example: query="gitlab" → [(58061, "GITLAB-US-EAST-1"), ...]
        """
        try:
            async with session.get(
                f"{self.BASE}/searchcomplete/data.json",
                params={"term": query},
                timeout=aiohttp.ClientTimeout(total=15),
            ) as resp:
                if resp.status != 200:
                    body = await resp.text()
                    logger.info(f"[asn] RIPE search HTTP {resp.status} for '{query}': {body[:100]}")
                    return []

                data    = await resp.json()
                results = data.get("data", {}).get("categories", [])
                asns    = []
                for cat in results:
                    if cat.get("category", "") in ("ASN", "asn", "Aut-num"):
                        for suggestion in cat.get("suggestions", []):
                            # Format: "AS58061 (GITLAB-US-EAST-1)"
                            label = suggestion.get("label", "")
                            m     = re.match(r"AS(\d+)\s*(?:\((.+?)\))?", label)
                            if m:
                                asn_num  = int(m.group(1))
                                asn_name = m.group(2) or label
                                asns.append((asn_num, asn_name))
                return asns

        except asyncio.TimeoutError:
            logger.info(f"[asn] RIPE name search timed out for '{query}'")
            return []
        except Exception as exc:
            logger.info(f"[asn] RIPE name search error '{query}': {exc}")
            return []


# ─────────────────────────────────────────────────────────────────────────────
# Prefix utilities
# ─────────────────────────────────────────────────────────────────────────────

def is_private_range(prefix: str) -> bool:
    try:
        net = ipaddress.ip_network(prefix, strict=False)
        return net.is_private or net.is_loopback or net.is_link_local
    except ValueError:
        return False


def prefix_host_count(prefix: str) -> int:
    try:
        return ipaddress.IPv4Network(prefix, strict=False).num_addresses
    except ValueError:
        return 0


def expand_prefix_to_ips(prefix: str, max_ips: int = 1024) -> List[str]:
    """Expand a small CIDR to individual IPs. Returns [] if too large."""
    try:
        net = ipaddress.IPv4Network(prefix, strict=False)
        if net.num_addresses > max_ips:
            return []
        return [str(ip) for ip in net.hosts()]
    except ValueError:
        return []


def _company_name_from_domain(domain: str) -> str:
    """
    Extract a company search term from a root domain.
    myshopify.com → "shopify"
    gitlab.com    → "gitlab"
    hackerone.com → "hackerone"
    """
    root  = domain.lower().strip().rstrip(".")
    parts = root.split(".")
    if len(parts) >= 2:
        root = parts[-2]

    # Strip common sub-brand prefixes
    for prefix in ("my", "get", "try", "app", "use", "go", "hello"):
        if root.startswith(prefix) and len(root) > len(prefix) + 3:
            root = root[len(prefix):]
            break

    return re.sub(r"[^a-z]", "", root)


# ─────────────────────────────────────────────────────────────────────────────
# Known CDN / cloud ASNs — skip their prefixes
# ─────────────────────────────────────────────────────────────────────────────

CDN_CLOUD_ASNS = {
    # Cloudflare
    13335, 209242, 132892, 395747,
    # Akamai — multiple ASNs (AS33905 seen for tesla.com)
    20940, 16625, 217644, 33905, 16702, 35994, 23455, 23454,
    18717, 18680, 12222, 17204, 7922, 40927,
    # Fastly
    54113,
    # AWS CloudFront / EC2 / various AWS regions
    16509, 14618, 8987, 7224,
    # GCP
    15169, 396982,
    # Azure / Microsoft
    8075, 8069, 3598, 6584,
    # Vercel / Netlify / GitHub Pages
    76153, 9026, 36459,
    # Incapsula / Imperva
    19551,
    # Sucuri
    30148,
    # BunnyCDN / KeyCDN / Limelight
    47172, 22822, 64120,
    # StackPath / MaxCDN
    33438, 13649,
    # Edgio (formerly Limelight)
    22822,
    # Discourse CDN (civilized discourse — seen in gitlab assets)
    # Note: 394230 is NOT a CDN; it's Discourse's own ASN — let it through
}


# ─────────────────────────────────────────────────────────────────────────────
# Main ASN mapper
# ─────────────────────────────────────────────────────────────────────────────

class ASNMapper:
    """
    Discovers all IP ranges owned by a target company.

    Phase 1 — IP-based:
      For each known asset IP → ipinfo.io → ASN number & name.
      If ASN is not a CDN/cloud provider → RIPE Stat → all IPv4 prefixes.

    Phase 2 — Name-based fallback (when all IPs are CDN-proxied):
      Extract company name from domain → RIPE Stat searchcomplete → matching ASNs.
      Filters to ASNs whose name contains the company keyword.
      Fetches prefixes for each matching ASN.
    """

    def __init__(
        self,
        rate_delay:       float = 1.0,
        max_prefix_size:  int   = 65536,   # skip /15 and larger
        skip_cdn:         bool  = True,
        ipinfo_token:     Optional[str] = None,
    ) -> None:
        self.rate_delay      = rate_delay
        self.max_prefix_size = max_prefix_size
        self.skip_cdn        = skip_cdn
        self._ipinfo         = IPInfoClient(token=ipinfo_token, rate_delay=rate_delay)
        self._ripe           = RIPEStatClient(rate_delay=rate_delay)

    async def map(
        self,
        assets:     list,
        program_id: str,
        tenant_id:  str = "default",
    ):
        """
        Yield ASNInfo objects for each unique non-CDN ASN discovered.
        Falls back to name search if all IPs resolve to CDN ASNs.
        """
        # Collect unique IPs and root domains
        all_ips:      Dict[str, str] = {}   # ip → source domain
        root_domains: Set[str]       = set()

        for asset in assets:
            for ip in (asset.ip_addresses or []):
                if ip and ip not in all_ips:
                    all_ips[ip] = asset.domain
            d     = asset.domain.lower().strip().rstrip(".")
            parts = d.split(".")
            if len(parts) >= 2:
                root_domains.add(".".join(parts[-2:]))

        if not all_ips:
            logger.warning("[asn] No IPs found — run prober first")
            return

        logger.info(
            f"[asn] Starting | unique_ips={len(all_ips)} | "
            f"root_domains={len(root_domains)} | program={program_id}"
        )

        seen_asns:   Set[int] = set()
        cdn_asns:    Set[int] = set()
        yielded_any: bool     = False

        # Phase 1 — IP lookup
        connector = aiohttp.TCPConnector(ssl=True, limit=5)
        async with aiohttp.ClientSession(connector=connector) as session:
            for ip, domain in all_ips.items():
                await asyncio.sleep(self.rate_delay * 0.5)

                asn_result = await self._ipinfo.ip_to_asn(session, ip)
                if not asn_result:
                    continue

                asn_number, asn_name = asn_result

                if asn_number in seen_asns:
                    continue
                seen_asns.add(asn_number)

                # Skip by ASN number OR by well-known CDN name patterns
                cdn_keywords = (
                    "cloudflare", "akamai", "fastly", "amazon", "amazonaws",
                    "google", "microsoft", "azure", "incapsula", "imperva",
                    "sucuri", "limelight", "edgio", "stackpath", "maxcdn",
                    "bunny", "keycdn",
                )
                is_cdn_name = any(kw in asn_name.lower() for kw in cdn_keywords)
                if self.skip_cdn and (asn_number in CDN_CLOUD_ASNS or is_cdn_name):
                    cdn_asns.add(asn_number)
                    logger.debug(
                        f"[asn] {ip} → AS{asn_number} ({asn_name}) — CDN/cloud, skipping"
                    )
                    continue

                logger.info(f"[asn] IP-based: AS{asn_number} ({asn_name}) via {ip}")
                await asyncio.sleep(self.rate_delay)

                async for result in self._fetch_asn_prefixes(
                    session, asn_number, asn_name, domain, program_id, tenant_id
                ):
                    yielded_any = True
                    yield result

        # Phase 2 — Name-based fallback
        all_cdn = (bool(cdn_asns) or not seen_asns) and not yielded_any
        if all_cdn:
            logger.info(
                f"[asn] All {len(cdn_asns)} ASN(s) are CDN-owned — "
                "switching to name-based search via RIPE Stat"
            )
            # Fresh session for Phase 2
            p2_connector = aiohttp.TCPConnector(ssl=True, limit=3)
            async with aiohttp.ClientSession(connector=p2_connector) as p2_session:
                for domain in root_domains:
                    company   = _company_name_from_domain(domain)
                    raw_label = domain.split(".")[-2] if "." in domain else domain
                    raw_label = re.sub(r"[^a-z]", "", raw_label.lower())

                    # Try stripped name first, then raw label if different
                    search_terms = [company]
                    if raw_label != company:
                        search_terms.append(raw_label)

                    for term in search_terms:
                        if not term or len(term) < 3:
                            continue

                        logger.info(f"[asn] Name search (RIPE Stat): '{term}' (from {domain})")
                        await asyncio.sleep(self.rate_delay)

                        candidates = await self._ripe.search_asns_by_name(p2_session, term)

                        if candidates:
                            logger.info(
                                f"[asn] RIPE returned {len(candidates)} candidate(s) for '{term}': "
                                + ", ".join(f"AS{n}({nm[:20]})" for n, nm in candidates[:5])
                            )

                        for asn_number, asn_name in candidates:
                            if asn_number in seen_asns or asn_number in CDN_CLOUD_ASNS:
                                continue
                            if term.lower() not in asn_name.lower():
                                logger.debug(
                                    f"[asn] Skipping AS{asn_number} ({asn_name}) — "
                                    f"'{term}' not in name"
                                )
                                continue

                            seen_asns.add(asn_number)
                            logger.info(f"[asn] ✓ Name match: AS{asn_number} ({asn_name})")
                            await asyncio.sleep(self.rate_delay)

                            async for result in self._fetch_asn_prefixes(
                                p2_session, asn_number, asn_name, domain,
                                program_id, tenant_id
                            ):
                                yielded_any = True
                                yield result

                        if yielded_any:
                            break   # found results — no need to try raw_label

        if not yielded_any:
            logger.info(
                "[asn] No company-owned ASNs found.\n"
                "  This is expected for heavily CDN-proxied targets.\n"
                "  The port scanner will still use known asset IPs."
            )

    async def _fetch_asn_prefixes(
        self,
        session:    aiohttp.ClientSession,
        asn_number: int,
        asn_name:   str,
        domain:     str,
        program_id: str,
        tenant_id:  str,
    ):
        """Fetch prefixes for one ASN via RIPE Stat and yield an ASNInfo."""
        ipv4_raw, ipv6_prefixes = await self._ripe.asn_prefixes(session, asn_number)

        ipv4_prefixes = [
            p for p in ipv4_raw
            if not is_private_range(p)
            and prefix_host_count(p) <= self.max_prefix_size
        ]

        total_ips = sum(prefix_host_count(p) for p in ipv4_prefixes)
        logger.info(
            f"[asn] AS{asn_number} ({asn_name}) | "
            f"raw={len(ipv4_raw)} prefixes | "
            f"usable={len(ipv4_prefixes)} | "
            f"~{total_ips:,} IPs"
        )

        if not ipv4_prefixes:
            return

        yield ASNInfo(
            tenant_id      = tenant_id,
            asn_number     = asn_number,
            asn_name       = asn_name,
            program_id     = program_id,
            domain         = domain,
            ip_prefixes    = ipv4_prefixes,
            ipv6_prefixes  = ipv6_prefixes[:50],
            description    = asn_name,
        )