"""
ZeroPoint :: modules/nuclei.py
================================
Asynchronous Nuclei wrapper — the vulnerability scanning worker.

Design decisions:
  1. Smart template selection — based on detected tech stack from Module 2,
     we select targeted template tags/paths instead of running all templates.
     This means 10x faster scans and dramatically lower noise.

  2. Streaming output — Nuclei's -jsonl output is parsed line-by-line as
     results stream in. No waiting for the full run to finish.

  3. Deduplication fingerprint — every finding is hashed (sha256) from
     template_id + domain + matched_at. This hash is the DB primary key,
     guaranteeing idempotency across multiple scan runs.

  4. Request/Response capture — -include-rr flag captures the raw HTTP
     exchange so you have a ready-made PoC without re-running manually.

Nuclei flags reference:
  -l            input list file
  -jsonl        structured JSON Lines output (one object per line)
  -silent       no banner/progress output
  -nc           no color (clean for log parsing)
  -severity     filter by severity (critical,high,medium)
  -c            template concurrency
  -bulk-size    bulk targets per template
  -rate-limit   global req/sec cap
  -timeout      per-request timeout
  -retries      retry count per request
  -include-rr   include raw request/response in output (PoC capture)
  -stats        emit progress stats (piped to stderr)
  -t            template paths (comma-separated)
  -tags         template tags filter
  -etags        exclude tags
  -rl           rate limit alias
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import tempfile
from typing import AsyncIterator, Dict, List, Optional, Set

from loguru import logger

from models import Finding, InterestLevel, ScanSeverity

# Domain keyword → technology hint
# Used when httpx can't fingerprint through a reverse proxy (e.g. Nginx in front of Kibana)
_DOMAIN_TECH_HINTS: dict[str, str] = {
    "kibana":        "kibana",
    "grafana":       "grafana",
    "elastic":       "elasticsearch",
    "elasticsearch": "elasticsearch",
    "jenkins":       "jenkins",
    "gitlab":        "gitlab",
    "jira":          "jira",
    "sonar":         "sonarqube",
    "code-review":   "sonarqube",
    "codereview":    "sonarqube",
    "pgadmin":       "pgadmin",
    "phpmyadmin":    "phpmyadmin",
    "airflow":       "airflow",
    "jupyter":       "jupyter",
    "vault":         "vault",
    "consul":        "consul",
    "prometheus":    "prometheus",
    "minio":         "minio",
    "rabbitmq":      "rabbitmq",
    "wordpress":     "wordpress",
    "wp-":           "wordpress",
}

# ─────────────────────────────────────────────────────────────────────────────
# Tech Stack → Nuclei Template Tag Mapping
# "If Module 2 detected X, run these Nuclei tags/template dirs"
# This is the intelligence layer — targeted > spray-and-pray
# ─────────────────────────────────────────────────────────────────────────────

TECH_TAG_MAP: Dict[str, List[str]] = {
    # CI/CD & DevOps (CRITICAL priority — almost always auth-bypassable)
    "jenkins":       ["jenkins"],
    "gitlab":        ["gitlab"],
    "grafana":       ["grafana"],
    "kibana":        ["kibana"],
    "airflow":       ["airflow"],
    "jupyter":       ["jupyter"],
    "vault":         ["vault"],
    "consul":        ["consul"],
    "argo":          ["argocd"],

    # Database admin panels
    "phpmyadmin":    ["phpmyadmin"],
    "pgadmin":       ["pgadmin"],
    "adminer":       ["adminer"],

    # CMS platforms
    "wordpress":     ["wordpress", "wp"],
    "drupal":        ["drupal"],
    "joomla":        ["joomla"],
    "magento":       ["magento"],

    # Application frameworks
    "laravel":       ["laravel"],
    "django":        ["django"],
    "spring":        ["spring", "springboot"],
    "struts":        ["apache", "struts"],
    "tomcat":        ["tomcat", "apache"],
    "weblogic":      ["weblogic", "oracle"],
    "jboss":         ["jboss"],

    # APIs & documentation
    "graphql":       ["graphql"],
    "swagger":       ["swagger", "openapi"],

    # Monitoring & observability
    "prometheus":    ["prometheus"],
    "grafana":       ["grafana"],
    "netdata":       ["netdata"],
    "zabbix":        ["zabbix"],
    "splunk":        ["splunk"],

    # Storage & messaging
    "minio":         ["minio"],
    "rabbitmq":      ["rabbitmq"],

    # Generic — always include for any alive host
    "__default__":   ["exposure", "misconfig", "takeover", "token", "default-login"],
}

# Tags that map to severity-critical CVEs for specific products
# When we see these technologies, ALSO run CVE templates
TECH_CVE_MAP: Dict[str, List[str]] = {
    "jenkins":   ["CVE-2016-9299", "CVE-2019-1003000", "CVE-2018-1000861"],
    "gitlab":    ["CVE-2021-22205", "CVE-2022-2992"],
    "spring":    ["CVE-2022-22963", "CVE-2022-22965"],   # Spring4Shell
    "log4j":     ["CVE-2021-44228", "CVE-2021-45046"],   # Log4Shell
    "struts":    ["CVE-2017-5638", "CVE-2018-11776"],
    "weblogic":  ["CVE-2019-2725", "CVE-2020-14882"],
    "tomcat":    ["CVE-2020-1938", "CVE-2019-0232"],
    "drupal":    ["CVE-2018-7600", "CVE-2019-6340"],
    "wordpress": ["CVE-2021-29447", "CVE-2020-28037"],
    "grafana":   ["CVE-2021-43798"],
    "jboss":     ["CVE-2017-12149", "CVE-2015-7501"],
}


def build_template_tags(technologies: List[str], interest_level: str) -> Set[str]:
    """
    Given a list of detected technologies and an interest level,
    return the optimal set of Nuclei template tags to run.

    Strategy:
      CRITICAL/HIGH assets with known tech  → targeted tech tags + CVE tags + defaults
      CRITICAL/HIGH assets with unknown tech → broad defaults + exposure + misconfig
      MEDIUM assets                          → defaults only (faster)
    """
    tags: Set[str] = set()

    # Always include the default baseline tags
    tags.update(TECH_TAG_MAP["__default__"])

    tech_lower = [t.lower() for t in technologies]

    matched_any = False
    for tech in tech_lower:
        for key, tag_list in TECH_TAG_MAP.items():
            if key == "__default__":
                continue
            if key in tech or tech in key:
                tags.update(tag_list)
                matched_any = True

                # Add CVE tags if available for this tech
                if key in TECH_CVE_MAP:
                    tags.update(TECH_CVE_MAP[key])

    # For CRITICAL assets with no specific tech match, cast a wider net
    if not matched_any and interest_level in ("critical", "high"):
        tags.update([
            "exposure", "misconfig", "default-login",
            "takeover", "unauth", "auth-bypass",
            "panel", "token", "secret",
        ])

    logger.debug(f"[nuclei] Template tags resolved: {sorted(tags)}")
    return tags


# ─────────────────────────────────────────────────────────────────────────────
# Finding deduplication fingerprint
# ─────────────────────────────────────────────────────────────────────────────

def make_finding_id(template_id: str, domain: str, matched_at: str) -> str:
    """
    SHA-256 fingerprint for a finding — the deduplication key.
    Same vuln on same endpoint = same hash across all scan runs.
    """
    raw = f"{template_id.lower()}|{domain.lower()}|{matched_at.lower()}"
    return hashlib.sha256(raw.encode()).hexdigest()


# ─────────────────────────────────────────────────────────────────────────────
# Nuclei JSON line parser
# ─────────────────────────────────────────────────────────────────────────────

def _parse_nuclei_line(raw: str, program_id: str, scan_run_id: str) -> Optional[Finding]:
    """
    Parse a single JSON line from `nuclei -jsonl` output into a Finding.

    Nuclei JSONL schema (key fields):
    {
      "template-id":    "CVE-2021-44228",
      "info": {
        "name":         "Log4j RCE",
        "severity":     "critical",
        "description":  "...",
        "reference":    ["https://nvd.nist.gov/..."],
        "tags":         ["cve","rce","log4j"]
      },
      "host":           "api.example.com",
      "matched-at":     "https://api.example.com/path",
      "matcher-name":   "jndi-callback",
      "curl-command":   "curl -X POST ...",
      "request":        "POST /path HTTP/1.1\n...",
      "response":       "HTTP/1.1 200 OK\n...",
      "extracted-results": ["10.0.0.1"],
      "timestamp":      "2024-01-01T00:00:00Z"
    }
    """
    try:
        data: dict = json.loads(raw)
    except json.JSONDecodeError:
        return None

    template_id = data.get("template-id", "").strip()
    info        = data.get("info", {})
    matched_at  = data.get("matched-at", "").strip()
    host        = data.get("host", "").strip().lower()

    if not template_id or not matched_at or not host:
        return None

    # Extract domain cleanly (strip protocol and path)
    import re
    m = re.search(r"https?://([^/:]+)", host)
    domain = m.group(1) if m else host
    domain = domain.lower().rstrip(".")

    # Map Nuclei severity string to our enum
    raw_sev  = info.get("severity", "unknown").lower().strip()
    try:
        severity = ScanSeverity(raw_sev)
    except ValueError:
        severity = ScanSeverity.UNKNOWN

    # Truncate request/response — we store PoC, not full dumps
    raw_request  = (data.get("request")  or "")[:3000]
    raw_response = (data.get("response") or "")[:2000]

    finding_id = make_finding_id(template_id, domain, matched_at)

    # A finding with no matcher_name means the template fired on request alone
    # with no response-body/status confirmation — flag it for manual review
    matcher_name = data.get("matcher-name") or data.get("matcher_name") or ""
    is_confirmed = bool(matcher_name.strip())

    return Finding(
        finding_id        = finding_id,
        program_id        = program_id,
        domain            = domain,
        template_id       = template_id,
        template_name     = info.get("name", template_id).strip(),
        severity          = severity,
        matched_at        = matched_at,
        matcher_name      = matcher_name or None,
        description       = info.get("description", "").strip() or None,
        reference         = info.get("reference") or [],
        tags              = info.get("tags") or [],
        curl_command      = data.get("curl-command"),
        request           = raw_request or None,
        response          = raw_response or None,
        extracted_results = data.get("extracted-results") or [],
        scan_run_id       = scan_run_id,
        confirmed         = is_confirmed,
    )


# ─────────────────────────────────────────────────────────────────────────────
# Safe line reader — handles lines that exceed asyncio's StreamReader buffer
# ─────────────────────────────────────────────────────────────────────────────

async def _read_lines_safe(stream: asyncio.StreamReader):
    """
    Async generator that yields decoded lines from a StreamReader.

    Unlike iterating `stream` directly, this handles `LimitOverrunError`
    (lines larger than the 4MB buffer limit) by reading in raw chunks and
    reassembling — no crash, no data loss.

    Root cause: nuclei's -include-rr embeds the full HTTP request+response
    in a single JSON line. Some targets (GraphQL introspection, large API
    docs, verbose error pages) return multi-megabyte bodies that blow past
    even a 4MB readline limit.
    """
    buffer = b""
    while True:
        try:
            chunk = await stream.readline()
            if not chunk:
                if buffer:
                    yield buffer.decode(errors="replace")
                break
            yield (buffer + chunk).decode(errors="replace")
            buffer = b""

        except ValueError:
            # LimitOverrunError → read the monster line in a raw chunk
            try:
                chunk = await stream.read(4 * 2 ** 20)
                buffer += chunk
                if buffer.endswith(b"\n"):
                    yield buffer.decode(errors="replace")
                    buffer = b""
                # else: accumulate until newline arrives
            except Exception as inner:
                logger.debug(f"[nuclei] Chunked read error (oversized line skipped): {inner}")
                buffer = b""

        except Exception as exc:
            logger.debug(f"[nuclei] Stream read error: {exc}")
            break


# ─────────────────────────────────────────────────────────────────────────────
# NucleiScanner Worker
# ─────────────────────────────────────────────────────────────────────────────

class NucleiScanner:
    """
    Async wrapper around the `nuclei` binary.

    Yields Finding objects as they stream from nuclei's stdout.
    Never accumulates all results in memory.

    Template sources supported (all run together):
      - Official nuclei-templates   (templates_path)
      - Community templates         (community_templates_path)
      - Your own custom templates   (custom_templates)
      - Fuzzing templates           (fuzzing_templates_path, opt-in)

    Usage:
        scanner = NucleiScanner(binary_path="nuclei", ...)
        async for finding in scanner.scan(assets, program_id, run_id):
            await db.upsert_finding(finding)
    """

    def __init__(
        self,
        binary_path:              str   = "nuclei",
        templates_path:           str   = "",    # Official PD templates
        community_templates_path: str   = "",    # nuclei-templates-community
        custom_templates:         str   = "",    # Your own templates dir
        fuzzing_templates_path:   str   = "",    # nuclei-templates/fuzzing (opt-in)
        severity:                 str   = "critical,high,medium,low,info",
        rate_limit:               int   = 50,
        concurrency:              int   = 25,
        bulk_size:                int   = 25,
        timeout:                  int   = 600,
        retries:                  int   = 1,
        exclude_tags:             str   = "dos",   # fuzz removed — user wants fuzzing
        include_tags:             str   = "",
        enable_fuzzing:           bool  = True,    # opt-in flag for fuzzing templates
    ) -> None:
        self.binary_path              = binary_path
        self.templates_path           = templates_path
        self.community_templates_path = community_templates_path
        self.custom_templates         = custom_templates
        self.fuzzing_templates_path   = fuzzing_templates_path
        self.severity                 = severity
        self.rate_limit               = rate_limit
        self.concurrency              = concurrency
        self.bulk_size                = bulk_size
        self.timeout                  = timeout
        self.retries                  = retries
        self.exclude_tags             = exclude_tags
        self.include_tags             = include_tags
        self.enable_fuzzing           = enable_fuzzing

    def _build_command(
        self,
        input_file:  str,
        output_file: str,
        tags:        Optional[Set[str]] = None,
    ) -> List[str]:
        """
        Assemble the full nuclei command line.

        Template priority order (nuclei merges all -t flags):
          1. Official nuclei-templates       (templates_path)
          2. nuclei-templates-community      (community_templates_path)
          3. Custom user templates           (custom_templates)
          4. Fuzzing templates               (fuzzing_templates_path, opt-in)

        IMPORTANT: If NO valid -t paths are supplied, nuclei falls back to its
        auto-managed ~/.nuclei-templates directory — this is the correct default
        and gives the full 9000+ template library.

        NOTE: -passive is intentionally NOT used. In Nuclei, -passive means
        "read traffic from a proxy/stdin, don't make live HTTP requests" which
        is a completely different feature. Fuzzing templates run fine without it.
        """
        cmd = [
            self.binary_path,
            "-l",          input_file,
            "-jsonl",
            "-silent",
            "-nc",                          # no colour codes — clean for parsing
            "-severity",   self.severity,
            "-c",          str(self.concurrency),
            "-bulk-size",  str(self.bulk_size),
            "-rate-limit", str(self.rate_limit),
            "-timeout",    "10",            # per-request timeout (sec)
            "-retries",    str(self.retries),
            "-include-rr",                  # capture raw HTTP request/response as PoC
            "-stats",                       # progress stats → stderr
            "-o",          output_file,     # backup output file alongside stdout
            "-matcher-status",              # only report confirmed matcher hits (reduces FPs)
            "-no-mhe",                      # disable matcher-based host errors (cleaner output)
        ]

        # ── Template sources ───────────────────────────────────────────────────
        # Only add -t flags for paths that actually exist on disk.
        # An unset/placeholder path (e.g. "/path/to/...") silently falls through
        # so nuclei continues to use its default ~/.nuclei-templates library.
        template_candidates = [
            self.templates_path,            # official PD templates
            self.community_templates_path,  # community templates
            self.custom_templates,          # user's own templates
        ]
        if self.enable_fuzzing and self.fuzzing_templates_path:
            template_candidates.append(self.fuzzing_templates_path)

        valid_sources: List[str] = []
        for src in template_candidates:
            if not src or not src.strip():
                continue                    # empty / unset
            src = src.strip()
            if not os.path.exists(src):
                logger.warning(
                    f"[nuclei] Template path does not exist, skipping: {src}\n"
                    f"         Update {src!r} in your .env or remove the setting."
                )
                continue
            valid_sources.append(src)
            cmd += ["-t", src]

        if not valid_sources:
            # No valid custom paths → nuclei auto-uses ~/.nuclei-templates (full library)
            logger.debug(
                "[nuclei] No custom -t paths configured or all paths invalid. "
                "Using nuclei default template library (~/.nuclei-templates)."
            )

        # ── Tag filtering ──────────────────────────────────────────────────────
        if tags:
            cmd += ["-tags", ",".join(sorted(tags))]
        if self.include_tags:
            cmd += ["-tags", self.include_tags]
        if self.exclude_tags:
            cmd += ["-etags", self.exclude_tags]

        return cmd

    async def scan(
        self,
        assets:        List,
        program_id:    str,
        scan_run_id:   str,
        no_tag_filter: bool = False,
    ) -> AsyncIterator[Finding]:
        """
        Scan a list of Asset objects. Yields Finding instances as Nuclei reports them.

        Args:
            no_tag_filter: Bypass tech-based tag selection and run the full
                           template library. Set automatically when assets have
                           no detected technologies (e.g. quick-scan mode).
        """
        if not assets:
            return

        if len(assets) <= 5:
            for asset in assets:
                async for finding in self._scan_single_asset(
                    asset, program_id, scan_run_id, no_tag_filter=no_tag_filter
                ):
                    yield finding
        else:
            async for finding in self._scan_batch(assets, program_id, scan_run_id):
                yield finding

    async def _scan_single_asset(
        self,
        asset,
        program_id:    str,
        scan_run_id:   str,
        no_tag_filter: bool = False,
    ) -> AsyncIterator[Finding]:
        """
        Targeted scan of one asset.

        If the asset has a known tech stack (from Module 2 fingerprinting),
        we build a targeted tag set. If not (quick-scan mode or unprobed asset),
        we run the full template library with no -tags filter for maximum coverage.
        """
        has_tech = bool(asset.technologies)

        if no_tag_filter or not has_tech:
            # No tech fingerprint available — run EVERYTHING at this severity.
            # This is the correct mode for --domain quick-scans and unprobed assets.
            logger.info(
                f"[nuclei] Full-sweep scan: {asset.domain} | "
                f"interest={asset.interest_level} | no tag filter (max coverage)"
            )
            async for finding in self._run_nuclei(
                targets=[asset.domain],
                program_id=program_id,
                scan_run_id=scan_run_id,
                no_tag_filter=True,
            ):
                yield finding
        else:
            # Tech stack known — run only relevant template tags (faster, less noise)
            tags = build_template_tags(asset.technologies, asset.interest_level)
            logger.info(
                f"[nuclei] Targeted scan: {asset.domain} | "
                f"interest={asset.interest_level} | tags={sorted(tags)}"
            )
            async for finding in self._run_nuclei(
                targets=[asset.domain],
                program_id=program_id,
                scan_run_id=scan_run_id,
                tags=tags,
            ):
                yield finding

    # Domain → tech keyword mapping for when httpx can't fingerprint through a reverse proxy
    _DOMAIN_TECH_HINTS = {
        "kibana":        "kibana",
        "grafana":       "grafana",
        "elastic":       "elasticsearch",
        "elasticsearch": "elasticsearch",
        "jenkins":       "jenkins",
        "gitlab":        "gitlab",
        "jira":          "jira",
        "sonar":         "sonarqube",
        "code-review":   "sonarqube",
        "pgadmin":       "pgadmin",
        "phpmyadmin":    "phpmyadmin",
        "airflow":       "airflow",
        "jupyter":       "jupyter",
        "vault":         "vault",
        "consul":        "consul",
        "grafana":       "grafana",
        "prometheus":    "prometheus",
        "minio":         "minio",
        "rabbitmq":      "rabbitmq",
    }

    async def _scan_batch(
        self,
        assets,
        program_id:  str,
        scan_run_id: str,
    ) -> AsyncIterator[Finding]:
        """Batch scan — union of all tech tags across the batch."""
        all_techs: list[str] = []

        for a in assets:
            # Use tech stack detected by httpx
            all_techs.extend(a.technologies)

            # Infer tech from domain name when httpx only sees the reverse proxy
            # e.g. kibana.example.com behind Nginx — httpx detects "Nginx", not "Kibana"
            domain_lower = a.domain.lower()
            for keyword, inferred_tech in _DOMAIN_TECH_HINTS.items():
                if keyword in domain_lower and inferred_tech not in all_techs:
                    logger.info(
                        f"[nuclei] Domain-inferred tech: {a.domain} → {inferred_tech} "
                        f"(httpx detected: {a.technologies or ['nothing']})"
                    )
                    all_techs.append(inferred_tech)

        # Use the highest interest level in the batch to govern tag selection
        level_order = ["noise", "low", "medium", "high", "critical"]
        max_level   = max(
            assets,
            key=lambda a: level_order.index(a.interest_level)
            if a.interest_level in level_order else 0
        ).interest_level

        tags    = build_template_tags(all_techs, max_level)
        targets = [a.domain for a in assets]

        logger.info(
            f"[nuclei] Batch scan | targets={len(targets)} | tags={sorted(tags)}"
        )
        async for finding in self._run_nuclei(
            targets=targets,
            program_id=program_id,
            scan_run_id=scan_run_id,
            tags=tags,
        ):
            yield finding

    async def _run_nuclei(
        self,
        targets:        List[str],
        program_id:     str,
        scan_run_id:    str,
        tags:           Optional[Set[str]] = None,
        no_tag_filter:  bool = False,
    ) -> AsyncIterator[Finding]:
        """
        Core executor — writes targets to tempfile, runs nuclei,
        streams stdout line-by-line, yields parsed Finding objects.

        Args:
            no_tag_filter: When True, omits -tags entirely so nuclei runs
                           its full template library. Used in quick-scan mode
                           where we have no tech fingerprint from Module 2.
        """
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".txt", prefix="zp_nuclei_in_",
            delete=False, encoding="utf-8",
        ) as inf:
            inf.write("\n".join(targets))
            input_path = inf.name

        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".jsonl", prefix="zp_nuclei_out_",
            delete=False, encoding="utf-8",
        ) as outf:
            output_path = outf.name

        # Pass tags=None when no_tag_filter=True — _build_command skips -tags
        effective_tags = None if no_tag_filter else tags
        cmd = self._build_command(input_path, output_path, effective_tags)

        # Always print the full command at INFO so it's visible without -v
        logger.info(f"[nuclei] COMMAND: {' '.join(cmd)}")

        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                limit=4 * 2 ** 20,   # 4MB per-line buffer
                                     # -include-rr embeds full HTTP request+response
                                     # in a single JSON line; GraphQL/API responses
                                     # can exceed 1MB easily
            )

            assert proc.stdout is not None
            hit_count = 0

            # Stream findings from stdout line-by-line.
            # If a line exceeds the 4MB buffer (extremely large response body),
            # we read it in chunks, reassemble, and continue — never crash.
            async for raw_line in _read_lines_safe(proc.stdout):
                line = raw_line.strip()
                if not line:
                    continue

                finding = _parse_nuclei_line(line, program_id, scan_run_id)
                if finding is not None:
                    hit_count += 1
                    yield finding

            # Collect stderr — nuclei writes stats + errors here
            _, stderr_bytes = await asyncio.wait_for(
                proc.communicate(), timeout=self.timeout
            )
            stderr = stderr_bytes.decode(errors="replace").strip()

            # Always show stderr — it contains template count and stats
            if stderr:
                logger.info(f"[nuclei] STDERR:\n{stderr[-800:]}")

            if proc.returncode not in (0, None):
                logger.debug(f"[nuclei] Exit code: {proc.returncode}")

            logger.success(
                f"[nuclei] Run complete | "
                f"targets={len(targets)} | findings={hit_count}"
            )

        except asyncio.TimeoutError:
            logger.error(
                f"[nuclei] Timed out after {self.timeout}s — "
                f"killing process and continuing"
            )
            try:
                proc.kill()
            except Exception:
                pass

        except FileNotFoundError:
            logger.error(
                f"[nuclei] Binary not found at '{self.binary_path}'. "
                "Install: go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
            )

        except Exception as exc:
            logger.exception(f"[nuclei] Unexpected error: {exc}")

        finally:
            for path in (input_path, output_path):
                try:
                    os.unlink(path)
                except OSError:
                    pass