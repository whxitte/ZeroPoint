"""
ZeroPoint :: modules/port_scanner.py
======================================
Asynchronous port scanning — two-phase approach:

  Phase 1 — Masscan (fast discovery)
    Sweeps all IPs for a target in seconds.
    Only cares which ports are open — no service info.
    Flags: -p (port ranges), --rate (packets/sec), --open-only, -oJ (JSON output)

  Phase 2 — Nmap (service fingerprint)
    Runs only against the open ports Masscan found.
    Identifies service name, product, version, and grabs banners.
    Flags: -sV (version detect), -sC (default scripts), --open, -oX (XML)

Why two phases:
  Masscan at 10,000 pps sweeps a /24 in under a second.
  Nmap with -sV on 65535 ports takes minutes per host.
  Combined: Masscan finds open ports fast, Nmap fingerprints only those.

Port triage rules (SERVICE_SEVERITY):
  Unauthenticated database services (Redis 6379, MongoDB 27017, ES 9200) → CRITICAL
  Admin UIs (Grafana 3000, Kibana 5601, pgAdmin 5050) → HIGH
  Dev services (Jupyter 8888, Airflow 8080) → HIGH
  SSH (22), HTTP (80/443) → INFO

Requirements:
  masscan — sudo apt install masscan  OR  go install github.com/robertdavidgraham/masscan
  nmap    — sudo apt install nmap

Note on privileges:
  Masscan requires raw socket access. Run as root or with:
    sudo setcap cap_net_raw+ep $(which masscan)
  If masscan is unavailable, the module falls back to Nmap-only mode.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import re
import tempfile
import xml.etree.ElementTree as ET
from typing import AsyncIterator, Dict, List, Optional, Tuple

from loguru import logger

from db.portscan_ops import make_port_finding_id
from models import PortFinding, PortFindingSeverity


# ─────────────────────────────────────────────────────────────────────────────
# Port → Service severity mapping
# ─────────────────────────────────────────────────────────────────────────────

SERVICE_SEVERITY: Dict[int, Tuple[str, PortFindingSeverity, str]] = {
    # ── CRITICAL: unauthenticated database / cache access ────────────────────
    6379:  ("redis",           PortFindingSeverity.CRITICAL, "Redis — often auth-free, full RW access"),
    27017: ("mongodb",         PortFindingSeverity.CRITICAL, "MongoDB — auth optional, data exposure"),
    27018: ("mongodb",         PortFindingSeverity.CRITICAL, "MongoDB replica set member"),
    9200:  ("elasticsearch",   PortFindingSeverity.CRITICAL, "Elasticsearch — unauthenticated API common"),
    9300:  ("elasticsearch",   PortFindingSeverity.CRITICAL, "Elasticsearch transport layer"),
    5984:  ("couchdb",         PortFindingSeverity.CRITICAL, "CouchDB — Futon admin often exposed"),
    11211: ("memcached",       PortFindingSeverity.CRITICAL, "Memcached — no auth, cache poisoning"),
    5432:  ("postgresql",      PortFindingSeverity.HIGH,     "PostgreSQL — check for weak/no auth"),
    3306:  ("mysql",           PortFindingSeverity.HIGH,     "MySQL — check for weak/no auth"),
    1433:  ("mssql",           PortFindingSeverity.HIGH,     "MSSQL — check for weak/no auth"),
    1521:  ("oracle",          PortFindingSeverity.HIGH,     "Oracle DB — check for weak/no auth"),

    # ── HIGH: admin UIs and dashboards ───────────────────────────────────────
    3000:  ("grafana",         PortFindingSeverity.HIGH,     "Grafana dashboard — default creds common"),
    5601:  ("kibana",          PortFindingSeverity.HIGH,     "Kibana — often no auth on internal nets"),
    9090:  ("prometheus",      PortFindingSeverity.HIGH,     "Prometheus metrics — internal data leak"),
    5050:  ("pgadmin",         PortFindingSeverity.HIGH,     "pgAdmin web UI"),
    8161:  ("activemq",        PortFindingSeverity.HIGH,     "ActiveMQ admin console"),
    15672: ("rabbitmq",        PortFindingSeverity.HIGH,     "RabbitMQ management UI — default creds"),
    9000:  ("portainer",       PortFindingSeverity.HIGH,     "Portainer Docker UI — admin access"),
    2375:  ("docker",          PortFindingSeverity.CRITICAL, "Docker daemon API — unauthenticated RCE"),
    2376:  ("docker-tls",      PortFindingSeverity.HIGH,     "Docker daemon API (TLS)"),
    4243:  ("docker",          PortFindingSeverity.CRITICAL, "Docker daemon API — alternate port"),

    # ── HIGH: development services ───────────────────────────────────────────
    8888:  ("jupyter",         PortFindingSeverity.HIGH,     "Jupyter Notebook — often token-less"),
    8080:  ("http-alt",        PortFindingSeverity.MEDIUM,   "HTTP alt port — admin panels common"),
    8443:  ("https-alt",       PortFindingSeverity.MEDIUM,   "HTTPS alt port"),
    9443:  ("https-alt",       PortFindingSeverity.MEDIUM,   "HTTPS alt port"),

    # ── MEDIUM: infrastructure / internal ────────────────────────────────────
    4369:  ("epmd",            PortFindingSeverity.MEDIUM,   "Erlang Port Mapper — RabbitMQ/CouchDB"),
    7077:  ("spark",           PortFindingSeverity.MEDIUM,   "Apache Spark master"),
    9092:  ("kafka",           PortFindingSeverity.MEDIUM,   "Apache Kafka — internal message bus"),
    2181:  ("zookeeper",       PortFindingSeverity.MEDIUM,   "ZooKeeper — Kafka/HBase coordination"),
    5044:  ("logstash",        PortFindingSeverity.MEDIUM,   "Logstash Beats input"),
    8125:  ("statsd",          PortFindingSeverity.MEDIUM,   "StatsD metrics"),
    6443:  ("kubernetes",      PortFindingSeverity.HIGH,     "Kubernetes API server"),
    10250: ("kubelet",         PortFindingSeverity.HIGH,     "Kubelet API — node-level access"),
    10255: ("kubelet-ro",      PortFindingSeverity.MEDIUM,   "Kubelet read-only API"),
    2379:  ("etcd",            PortFindingSeverity.HIGH,     "etcd — Kubernetes cluster state"),
    2380:  ("etcd-peer",       PortFindingSeverity.HIGH,     "etcd peer communication"),

    # ── INFO: expected public services ───────────────────────────────────────
    22:    ("ssh",             PortFindingSeverity.INFO,     "SSH"),
    80:    ("http",            PortFindingSeverity.INFO,     "HTTP"),
    443:   ("https",           PortFindingSeverity.INFO,     "HTTPS"),
    21:    ("ftp",             PortFindingSeverity.MEDIUM,   "FTP — plaintext, check anonymous"),
    25:    ("smtp",            PortFindingSeverity.INFO,     "SMTP"),
    53:    ("dns",             PortFindingSeverity.INFO,     "DNS"),
    3389:  ("rdp",             PortFindingSeverity.HIGH,     "RDP — brute-force target"),
}

# Port ranges to scan — focused on high-value ports, not all 65535
# Masscan with --rate=1000 covers this in ~2s per host
DEFAULT_PORTS = (
    "21-23,25,53,80,443,445,1433,1521,2181,2375-2376,2379-2380,"
    "3000,3306,3389,4243,4369,5044,5050,5432,5601,5984,"
    "6379,6443,7077,8080,8125,8161,8443,8888,9000,9090,9092,"
    "9200,9300,9443,10250,10255,11211,15672,27017-27018"
)


# ─────────────────────────────────────────────────────────────────────────────
# Severity classifier
# ─────────────────────────────────────────────────────────────────────────────

def classify_port(
    port: int,
    service: Optional[str] = None,
    product: Optional[str] = None,
) -> Tuple[PortFindingSeverity, str]:
    """
    Assign severity and reason to an open port.
    Uses port number first, then falls back to service name matching.
    """
    if port in SERVICE_SEVERITY:
        _, sev, reason = SERVICE_SEVERITY[port]
        return sev, reason

    # Service name fallback for ports not in the table
    svc_lower = (service or "").lower() + " " + (product or "").lower()
    for keyword, severity, reason in [
        ("redis",          PortFindingSeverity.CRITICAL, "Redis service detected"),
        ("mongodb",        PortFindingSeverity.CRITICAL, "MongoDB service detected"),
        ("elasticsearch",  PortFindingSeverity.CRITICAL, "Elasticsearch detected"),
        ("docker",         PortFindingSeverity.CRITICAL, "Docker API detected"),
        ("jupyter",        PortFindingSeverity.HIGH,     "Jupyter detected"),
        ("grafana",        PortFindingSeverity.HIGH,     "Grafana detected"),
        ("kibana",         PortFindingSeverity.HIGH,     "Kibana detected"),
        ("postgres",       PortFindingSeverity.HIGH,     "PostgreSQL detected"),
        ("mysql",          PortFindingSeverity.HIGH,     "MySQL detected"),
        ("rdp",            PortFindingSeverity.HIGH,     "RDP detected"),
        ("vnc",            PortFindingSeverity.HIGH,     "VNC detected — often no auth"),
        ("ftp",            PortFindingSeverity.MEDIUM,   "FTP detected"),
    ]:
        if keyword in svc_lower:
            return severity, reason

    return PortFindingSeverity.INFO, f"Open port {port}"



# ─────────────────────────────────────────────────────────────────────────────
# Port range expander
# ─────────────────────────────────────────────────────────────────────────────

def _expand_port_ranges(ports_str: str) -> List[int]:
    """
    Expand a comma-separated port spec with ranges into a flat list.
    "21-23,80,443,6379" → [21, 22, 23, 80, 443, 6379]
    """
    result = []
    for part in ports_str.split(","):
        part = part.strip()
        if "-" in part:
            try:
                start, end = part.split("-", 1)
                result.extend(range(int(start.strip()), int(end.strip()) + 1))
            except ValueError:
                pass
        elif part.isdigit():
            result.append(int(part))
    return result


# ─────────────────────────────────────────────────────────────────────────────
# Masscan phase
# ─────────────────────────────────────────────────────────────────────────────

async def _run_masscan(
    targets: List[str],
    ports:   str,
    rate:    int,
    binary:  str,
) -> Dict[str, List[int]]:
    """
    Run masscan against a list of IPs/CIDRs.
    Returns {ip: [open_ports]} mapping.
    """
    if not targets:
        return {}

    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".txt", prefix="zp_masscan_in_",
        delete=False, encoding="utf-8",
    ) as f:
        f.write("\n".join(targets))
        input_path = f.name

    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".json", prefix="zp_masscan_out_",
        delete=False, encoding="utf-8",
    ) as f:
        output_path = f.name

    cmd = [
        binary,
        "-iL",       input_path,
        "-p",        ports,
        "--rate",    str(rate),
        "--open-only",            # only report open ports
        "-oJ",       output_path, # JSON output
        "--wait",    "3",         # wait 3s after last packet before stopping
    ]

    logger.debug(f"[masscan] CMD: {' '.join(cmd)}")

    results: Dict[str, List[int]] = {}
    perm_error = False

    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        _, stderr_bytes = await asyncio.wait_for(proc.communicate(), timeout=300)
        stderr = stderr_bytes.decode(errors="replace").strip()

        # Detect permission / capability errors — masscan needs raw sockets
        if stderr:
            stderr_lower = stderr.lower()
            if any(kw in stderr_lower for kw in (
                "permission denied", "operation not permitted",
                "failed to detect", "cap_net_raw", "rawsock",
                "cannot open rawsock", "must be run as root",
            )):
                logger.warning(
                    "[masscan] ⚠️  Permission denied — masscan needs raw socket access.\n"
                    "  Fix (pick one):\n"
                    "    Option A (recommended): sudo setcap cap_net_raw+ep $(which masscan)\n"
                    "    Option B: run the scanner with sudo\n"
                    "  Auto-falling back to Nmap-only mode for this run."
                )
                perm_error = True
            else:
                logger.debug(f"[masscan] stderr: {stderr[-300:]}")

        # Parse JSON output
        if not perm_error and os.path.exists(output_path) and os.path.getsize(output_path) > 10:
            with open(output_path, encoding="utf-8", errors="replace") as fh:
                raw = fh.read().strip()
                # masscan JSON is a list but may have a trailing comma making it invalid
                raw = raw.rstrip(",\n").rstrip(",")
                if not raw.startswith("["):
                    raw = "[" + raw + "]"
                try:
                    data = json.loads(raw)
                    for entry in data:
                        ip    = entry.get("ip", "").strip()
                        ports_list = entry.get("ports", [])
                        if ip:
                            results.setdefault(ip, [])
                            for p in ports_list:
                                port_num = p.get("port")
                                if port_num:
                                    results[ip].append(int(port_num))
                except json.JSONDecodeError as exc:
                    logger.warning(f"[masscan] JSON parse error: {exc}")

        if not perm_error:
            logger.info(f"[masscan] Found {len(results)} hosts with open ports")

    except FileNotFoundError:
        logger.error(
            f"[masscan] Binary not found at '{binary}'. "
            "Install: sudo apt install masscan  OR  see https://github.com/robertdavidgraham/masscan"
        )
    except asyncio.TimeoutError:
        logger.warning("[masscan] Timed out — killing process")
        try:
            proc.kill()
        except Exception:
            pass
    except Exception as exc:
        logger.exception(f"[masscan] Unexpected error: {exc}")
    finally:
        for path in (input_path, output_path):
            try:
                os.unlink(path)
            except OSError:
                pass

    return results, perm_error


# ─────────────────────────────────────────────────────────────────────────────
# Nmap phase — service fingerprint on specific ports
# ─────────────────────────────────────────────────────────────────────────────

async def _run_nmap(
    ip:     str,
    ports:  List[int],
    binary: str,
    timeout: int = 120,
) -> List[Dict]:
    """
    Run nmap -sV -sC against specific open ports on one IP.
    Returns list of service dicts: {port, protocol, service, product, banner}
    """
    if not ports:
        return []

    port_str = ",".join(str(p) for p in sorted(ports))

    with tempfile.NamedTemporaryFile(
        suffix=".xml", prefix="zp_nmap_out_",
        delete=False,
    ) as f:
        output_path = f.name

    cmd = [
        binary,
        "-sV",                        # service/version detection
        "--version-intensity", "5",   # 0-9, 5 is balanced
        "-sC",                        # default scripts (grabs banners, checks auth)
        "--open",                     # only show open ports
        "-p", port_str,
        "-oX", output_path,           # XML output
        "--host-timeout", f"{timeout}s",
        ip,
    ]

    logger.debug(f"[nmap] CMD: {' '.join(cmd)}")

    services: List[Dict] = []

    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        _, stderr_bytes = await asyncio.wait_for(proc.communicate(), timeout=timeout + 30)

        # Parse XML output
        if os.path.exists(output_path) and os.path.getsize(output_path) > 50:
            try:
                tree = ET.parse(output_path)
                root = tree.getroot()
                for host in root.findall("host"):
                    ports_elem = host.find("ports")
                    if ports_elem is None:
                        continue
                    for port_elem in ports_elem.findall("port"):
                        state = port_elem.find("state")
                        if state is None or state.get("state") != "open":
                            continue
                        port_num  = int(port_elem.get("portid", 0))
                        protocol  = port_elem.get("protocol", "tcp")
                        svc_elem  = port_elem.find("service")
                        svc_name  = svc_elem.get("name", "") if svc_elem is not None else ""
                        product   = ""
                        if svc_elem is not None:
                            product = " ".join(filter(None, [
                                svc_elem.get("product", ""),
                                svc_elem.get("version", ""),
                                svc_elem.get("extrainfo", ""),
                            ])).strip()

                        # Collect script output as banner
                        banner_parts = []
                        for script in port_elem.findall("script"):
                            output = script.get("output", "").strip()
                            if output:
                                banner_parts.append(f"[{script.get('id')}] {output}")
                        banner = "\n".join(banner_parts)[:500] or None

                        services.append({
                            "port":     port_num,
                            "protocol": protocol,
                            "service":  svc_name,
                            "product":  product or None,
                            "banner":   banner,
                        })
            except ET.ParseError as exc:
                logger.warning(f"[nmap] XML parse error for {ip}: {exc}")

    except FileNotFoundError:
        logger.error(
            f"[nmap] Binary not found at '{binary}'. "
            "Install: sudo apt install nmap"
        )
    except asyncio.TimeoutError:
        logger.warning(f"[nmap] Timed out on {ip}")
        try:
            proc.kill()
        except Exception:
            pass
    except Exception as exc:
        logger.exception(f"[nmap] Unexpected error on {ip}: {exc}")
    finally:
        try:
            os.unlink(output_path)
        except OSError:
            pass

    return services


# ─────────────────────────────────────────────────────────────────────────────
# Main scanner class
# ─────────────────────────────────────────────────────────────────────────────

class PortScanner:
    """
    Two-phase port scanner: Masscan (fast discovery) → Nmap (fingerprint).

    If masscan is not available, falls back to Nmap-only mode scanning
    the default port list directly. Slower but no privilege requirement.

    Usage:
        scanner = PortScanner()
        async for finding in scanner.scan(assets, program_id, run_id):
            await db.upsert_port_finding(finding)
    """

    def __init__(
        self,
        masscan_binary: str  = "masscan",
        nmap_binary:    str  = "nmap",
        ports:          str  = DEFAULT_PORTS,
        masscan_rate:   int  = 1000,    # packets/sec — keep low to avoid WAF bans
        nmap_timeout:   int  = 120,     # seconds per host
        skip_nmap:      bool = False,   # masscan-only mode (no service fingerprint)
    ) -> None:
        self.masscan_binary = masscan_binary
        self.nmap_binary    = nmap_binary
        self.ports          = ports
        self.masscan_rate   = masscan_rate
        self.nmap_timeout   = nmap_timeout
        self.skip_nmap      = skip_nmap

    async def scan(
        self,
        assets:     List,        # Asset objects with .domain and .ip_addresses
        program_id: str,
        run_id:     str,
    ) -> AsyncIterator[PortFinding]:
        """
        Scan a list of Asset objects. Yields PortFinding instances.

        Assets must have been probed (probe_status=alive) and have
        ip_addresses populated from Module 2.
        """
        # Build IP → domain mapping from asset list
        ip_to_domain: Dict[str, str] = {}
        all_ips: List[str] = []

        for asset in assets:
            for ip in (asset.ip_addresses or []):
                if ip and ip not in ip_to_domain:
                    ip_to_domain[ip] = asset.domain
                    all_ips.append(ip)

        if not all_ips:
            logger.warning(
                "[portscan] No IP addresses found in asset list. "
                "Run Module 2 (prober) first to populate ip_addresses."
            )
            return

        logger.info(
            f"[portscan] Starting scan | "
            f"assets={len(assets)} | unique_ips={len(all_ips)} | "
            f"ports={self.ports[:60]}..."
        )

        # Phase 1 — Masscan (fast)
        import shutil
        use_masscan = shutil.which(self.masscan_binary) is not None

        masscan_perm_error = False

        if use_masscan:
            logger.info(f"[portscan] Phase 1: Masscan @ {self.masscan_rate} pps")
            open_ports_by_ip, masscan_perm_error = await _run_masscan(
                all_ips, self.ports, self.masscan_rate, self.masscan_binary
            )
        else:
            logger.warning(
                f"[portscan] masscan not found at '{self.masscan_binary}' — "
                "falling back to Nmap-only mode (slower). "
                "Install: sudo apt install masscan"
            )
            open_ports_by_ip = {}

        # If masscan returned nothing due to permission error, fall back to Nmap-only
        if masscan_perm_error or (use_masscan and not open_ports_by_ip):
            if not masscan_perm_error:
                logger.info("[portscan] Masscan found no open ports — skipping Nmap phase")
                return
            # Permission error → fall back to Nmap-only (slower but works without root)
            logger.info("[portscan] Falling back to Nmap-only mode — scanning all ports directly")
            use_masscan = False
            open_ports_by_ip = {ip: [] for ip in all_ips}

        # Phase 2 — Nmap per host (service fingerprint)
        if self.skip_nmap:
            # Masscan-only: create basic findings without service info
            for ip, ports in open_ports_by_ip.items():
                domain = ip_to_domain.get(ip, ip)
                for port in ports:
                    sev, reason = classify_port(port)
                    yield PortFinding(
                        finding_id = make_port_finding_id(ip, port, "tcp"),
                        program_id = program_id,
                        domain     = domain,
                        ip         = ip,
                        port       = port,
                        protocol   = "tcp",
                        severity   = sev,
                        reason     = reason,
                        scan_run_id = run_id,
                    )
            return

        logger.info(f"[portscan] Phase 2: Nmap fingerprint on {len(open_ports_by_ip)} host(s)")

        for ip, discovered_ports in open_ports_by_ip.items():
            domain = ip_to_domain.get(ip, ip)

            # In Nmap-only mode, expand the port list (handles ranges like "80,443,6379-6381")
            # In masscan mode, use the discovered open ports directly
            if use_masscan and discovered_ports:
                ports_to_scan = discovered_ports
            else:
                ports_to_scan = _expand_port_ranges(self.ports)

            services = await _run_nmap(ip, ports_to_scan, self.nmap_binary, self.nmap_timeout)

            if not services and use_masscan and discovered_ports:
                # Nmap found nothing new — emit basic findings from masscan
                services = [
                    {"port": p, "protocol": "tcp", "service": None, "product": None, "banner": None}
                    for p in discovered_ports
                ]

            for svc in services:
                port     = svc["port"]
                protocol = svc.get("protocol", "tcp")
                service  = svc.get("service") or None
                product  = svc.get("product") or None
                banner   = svc.get("banner") or None

                sev, reason = classify_port(port, service, product)

                finding = PortFinding(
                    finding_id  = make_port_finding_id(ip, port, protocol),
                    program_id  = program_id,
                    domain      = domain,
                    ip          = ip,
                    port        = port,
                    protocol    = protocol,
                    service     = service,
                    product     = product,
                    banner      = banner,
                    severity    = sev,
                    reason      = reason,
                    scan_run_id = run_id,
                )
                yield finding

            if services:
                svc_summary = ", ".join(
                    f"{s['port']}/{s.get('service', '?')}" for s in services[:8]
                )
                logger.info(f"[portscan] {ip} ({domain}): {svc_summary}")