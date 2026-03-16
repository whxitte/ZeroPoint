"""
ZeroPoint :: core/fingerprint.py
==================================
Technology fingerprint → Interest Level classifier.

This is the triage brain of ZeroPoint. It examines the probe data
returned by httpx (technologies, HTTP title, status code, URL, server
header) and assigns a priority score so the vulnerability scanner
(Module 3) knows what to hit first.

Design philosophy:
  - Rules are DATA, not code — edit the rule tables, not the logic.
  - Every classification decision is documented in `interest_reasons`
    so the researcher understands WHY an asset was flagged.
  - False positives are acceptable at CRITICAL/HIGH; false negatives
    at those levels are not. Err on the side of flagging.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import List, Optional, Tuple

from models import InterestLevel, ProbeResult


# ─────────────────────────────────────────────────────────────────────────────
# Rule Tables — EDIT THESE to tune triage sensitivity
# ─────────────────────────────────────────────────────────────────────────────

# (pattern_to_match_against_tech_or_server, reason_string, InterestLevel)
# Patterns are case-insensitive substring matches.

TECH_RULES: List[Tuple[str, str, InterestLevel]] = [
    # ── CRITICAL: High-value internal tools, usually auth-bypass goldmines ──
    ("jenkins",          "Jenkins CI/CD exposed",          InterestLevel.CRITICAL),
    ("gitlab",           "GitLab instance exposed",         InterestLevel.CRITICAL),
    ("jira",             "Jira project management exposed", InterestLevel.CRITICAL),
    ("confluence",       "Confluence wiki exposed",         InterestLevel.CRITICAL),
    ("grafana",          "Grafana dashboard exposed",       InterestLevel.CRITICAL),
    ("kibana",           "Kibana log dashboard exposed",    InterestLevel.CRITICAL),
    ("elasticsearch",    "Elasticsearch node exposed",      InterestLevel.CRITICAL),
    ("kubernetes",       "Kubernetes dashboard exposed",    InterestLevel.CRITICAL),
    ("k8s",              "Kubernetes component exposed",    InterestLevel.CRITICAL),
    ("airflow",          "Apache Airflow exposed",          InterestLevel.CRITICAL),
    ("jupyterhub",       "JupyterHub exposed",              InterestLevel.CRITICAL),
    ("jupyter",          "Jupyter notebook exposed",        InterestLevel.CRITICAL),
    ("vault",            "HashiCorp Vault exposed",         InterestLevel.CRITICAL),
    ("consul",           "HashiCorp Consul exposed",        InterestLevel.CRITICAL),
    ("pgadmin",          "pgAdmin DB admin exposed",        InterestLevel.CRITICAL),
    ("phpmyadmin",       "phpMyAdmin exposed",              InterestLevel.CRITICAL),
    ("adminer",          "Adminer DB panel exposed",        InterestLevel.CRITICAL),
    ("sonarqube",        "SonarQube exposed",               InterestLevel.CRITICAL),
    ("travis",           "Travis CI exposed",               InterestLevel.CRITICAL),
    ("circleci",         "CircleCI exposed",                InterestLevel.CRITICAL),
    ("argo",             "Argo CD/Workflows exposed",       InterestLevel.CRITICAL),

    # ── HIGH: Commonly vulnerable / interesting tech ─────────────────────────
    ("wordpress",        "WordPress CMS",                   InterestLevel.HIGH),
    ("wp-login",         "WordPress login page",            InterestLevel.HIGH),
    ("drupal",           "Drupal CMS",                      InterestLevel.HIGH),
    ("joomla",           "Joomla CMS",                      InterestLevel.HIGH),
    ("magento",          "Magento ecommerce",               InterestLevel.HIGH),
    ("laravel",          "Laravel framework",               InterestLevel.HIGH),
    ("django",           "Django framework",                InterestLevel.HIGH),
    ("rails",            "Ruby on Rails",                   InterestLevel.HIGH),
    ("tomcat",           "Apache Tomcat",                   InterestLevel.HIGH),
    ("weblogic",         "Oracle WebLogic",                 InterestLevel.HIGH),
    ("jboss",            "JBoss/WildFly",                   InterestLevel.HIGH),
    ("struts",           "Apache Struts",                   InterestLevel.HIGH),
    ("spring",           "Spring Boot",                     InterestLevel.HIGH),
    ("graphql",          "GraphQL endpoint",                InterestLevel.HIGH),
    ("swagger",          "Swagger/OpenAPI docs exposed",    InterestLevel.HIGH),
    ("openapi",          "OpenAPI spec exposed",            InterestLevel.HIGH),
    ("prometheus",       "Prometheus metrics exposed",      InterestLevel.HIGH),
    ("netdata",          "Netdata monitoring exposed",      InterestLevel.HIGH),
    ("zabbix",           "Zabbix monitoring exposed",       InterestLevel.HIGH),
    ("splunk",           "Splunk exposed",                  InterestLevel.HIGH),
    ("minio",            "MinIO object storage exposed",    InterestLevel.HIGH),
    ("redis",            "Redis web interface exposed",     InterestLevel.HIGH),
    ("rabbitmq",         "RabbitMQ management exposed",     InterestLevel.HIGH),
    ("apache",           "Apache HTTP Server",              InterestLevel.MEDIUM),
    ("nginx",            "Nginx web server",                InterestLevel.MEDIUM),

    # ── MEDIUM: Worth scanning but lower signal ───────────────────────────────
    ("php",              "PHP application",                 InterestLevel.MEDIUM),
    ("asp.net",          "ASP.NET application",             InterestLevel.MEDIUM),
    ("aspx",             "ASP.NET application",             InterestLevel.MEDIUM),
    ("coldfusion",       "ColdFusion application",          InterestLevel.MEDIUM),
    ("iis",              "Microsoft IIS",                   InterestLevel.MEDIUM),
    ("express",          "Node.js/Express",                 InterestLevel.MEDIUM),
    ("nodejs",           "Node.js application",             InterestLevel.MEDIUM),

    # ── NOISE: Hosting/CDN defaults — low value ───────────────────────────────
    ("cloudflare",       "Cloudflare CDN (default page)",   InterestLevel.NOISE),
    ("github pages",     "GitHub Pages static site",        InterestLevel.NOISE),
]

# HTTP title keyword rules — matched against lowercase title string
TITLE_RULES: List[Tuple[str, str, InterestLevel]] = [
    # ── CRITICAL ─────────────────────────────────────────────────────────────
    ("admin",            "Admin keyword in title",          InterestLevel.CRITICAL),
    ("dashboard",        "Dashboard keyword in title",      InterestLevel.CRITICAL),
    ("internal",         "Internal resource keyword",       InterestLevel.CRITICAL),
    ("jenkins",          "Jenkins in title",                InterestLevel.CRITICAL),
    ("kibana",           "Kibana in title",                 InterestLevel.CRITICAL),
    ("grafana",          "Grafana in title",                InterestLevel.CRITICAL),
    ("gitlab",           "GitLab in title",                 InterestLevel.CRITICAL),
    ("airflow",          "Airflow in title",                InterestLevel.CRITICAL),
    ("jupyter",          "Jupyter in title",                InterestLevel.CRITICAL),
    ("phpmy",            "phpMyAdmin in title",             InterestLevel.CRITICAL),
    ("pgadmin",          "pgAdmin in title",                InterestLevel.CRITICAL),

    # ── HIGH ──────────────────────────────────────────────────────────────────
    ("login",            "Login page",                      InterestLevel.HIGH),
    ("sign in",          "Sign-in page",                    InterestLevel.HIGH),
    ("portal",           "Portal keyword in title",         InterestLevel.HIGH),
    ("control panel",    "Control panel in title",          InterestLevel.HIGH),
    ("management",       "Management interface",            InterestLevel.HIGH),
    ("swagger",          "Swagger UI docs",                 InterestLevel.HIGH),
    ("api documentation","API documentation exposed",       InterestLevel.HIGH),
    ("graphql",          "GraphQL playground/IDE",          InterestLevel.HIGH),
    ("staging",          "Staging environment",             InterestLevel.HIGH),
    ("dev ",             "Development environment",         InterestLevel.HIGH),
    ("test ",            "Test environment",                InterestLevel.HIGH),
    ("beta",             "Beta environment",                InterestLevel.HIGH),
    ("upload",           "File upload functionality",       InterestLevel.HIGH),

    # ── MEDIUM ────────────────────────────────────────────────────────────────
    ("404",              "Custom 404 — target is real",     InterestLevel.MEDIUM),
    ("403",              "403 Forbidden — potentially bypassable", InterestLevel.MEDIUM),
    ("register",         "Registration page",               InterestLevel.MEDIUM),
    ("checkout",         "Checkout/payment flow",           InterestLevel.MEDIUM),

    # ── NOISE ─────────────────────────────────────────────────────────────────
    ("default page",     "Server default page",             InterestLevel.NOISE),
    ("welcome to nginx", "Nginx default page",              InterestLevel.NOISE),
    ("coming soon",      "Coming soon page",                InterestLevel.NOISE),
    ("parked domain",    "Parked domain",                   InterestLevel.NOISE),
    ("domain for sale",  "Domain for sale",                 InterestLevel.NOISE),
]

# URL / domain path pattern rules (matched against the full URL)
URL_RULES: List[Tuple[str, str, InterestLevel]] = [
    (r"admin\.",         "admin.* subdomain",               InterestLevel.CRITICAL),
    (r"jenkins\.",       "jenkins.* subdomain",             InterestLevel.CRITICAL),
    (r"jira\.",          "jira.* subdomain",                InterestLevel.CRITICAL),
    (r"kibana\.",        "kibana.* subdomain",              InterestLevel.CRITICAL),
    (r"grafana\.",       "grafana.* subdomain",             InterestLevel.CRITICAL),
    (r"gitlab\.",        "gitlab.* subdomain",              InterestLevel.CRITICAL),
    (r"git\.",           "git.* subdomain",                 InterestLevel.CRITICAL),
    (r"vault\.",         "vault.* subdomain",               InterestLevel.CRITICAL),
    (r"internal\.",      "internal.* subdomain",            InterestLevel.CRITICAL),
    (r"dev\.",           "dev.* subdomain",                 InterestLevel.HIGH),
    (r"staging\.",       "staging.* subdomain",             InterestLevel.HIGH),
    (r"beta\.",          "beta.* subdomain",                InterestLevel.HIGH),
    (r"test\.",          "test.* subdomain",                InterestLevel.HIGH),
    (r"uat\.",           "UAT subdomain",                   InterestLevel.HIGH),
    (r"api\.",           "API subdomain",                   InterestLevel.HIGH),
    (r"vpn\.",           "VPN subdomain",                   InterestLevel.HIGH),
    (r"mail\.",          "Mail server subdomain",           InterestLevel.MEDIUM),
    (r"smtp\.",          "SMTP server subdomain",           InterestLevel.MEDIUM),
    (r"ftp\.",           "FTP server subdomain",            InterestLevel.MEDIUM),
    (r"cdn\.",           "CDN subdomain (low value)",       InterestLevel.LOW),
    (r"static\.",        "Static asset subdomain",          InterestLevel.LOW),
    (r"assets\.",        "Assets subdomain",                InterestLevel.LOW),
    (r"img\.",           "Image CDN subdomain",             InterestLevel.NOISE),
]

# HTTP status code rules (applied last, lowest precedence)
STATUS_RULES: List[Tuple[int, str, InterestLevel]] = [
    (401, "HTTP 401 Unauthorized — auth bypass target",  InterestLevel.HIGH),
    (403, "HTTP 403 Forbidden — potential bypass",       InterestLevel.MEDIUM),
    (302, "Redirect — follow and classify",              InterestLevel.LOW),
    (200, "HTTP 200 OK",                                 InterestLevel.LOW),
    (500, "HTTP 500 Server Error — potential info leak", InterestLevel.MEDIUM),
    (503, "HTTP 503 Service Unavailable",                InterestLevel.LOW),
]

# Level precedence for merging multiple rule hits
_LEVEL_ORDER = {
    InterestLevel.NOISE:    0,
    InterestLevel.LOW:      1,
    InterestLevel.MEDIUM:   2,
    InterestLevel.HIGH:     3,
    InterestLevel.CRITICAL: 4,
}


# ─────────────────────────────────────────────────────────────────────────────
# Classifier
# ─────────────────────────────────────────────────────────────────────────────

class FingerprintClassifier:
    """
    Stateless classifier. Call `classify(probe_result)` to annotate
    a ProbeResult with an `interest_level` and `interest_reasons`.

    Returns a new ProbeResult (immutable update) — never mutates in place.
    """

    def classify(self, probe: ProbeResult) -> ProbeResult:
        """
        Apply all rule tables to `probe` and return an updated copy with
        `interest_level` and `interest_reasons` populated.
        """
        best_level  = InterestLevel.LOW
        reasons: List[str] = []

        # ── 1. URL / domain name rules ────────────────────────────────────
        for pattern, reason, level in URL_RULES:
            if re.search(pattern, probe.domain, re.IGNORECASE):
                best_level, reasons = self._merge(best_level, level, reason, reasons)

        # ── 2. Technology rules ──────────────────────────────────────────
        tech_blob = " ".join(probe.technologies).lower()
        if probe.web_server:
            tech_blob += " " + probe.web_server.lower()

        for keyword, reason, level in TECH_RULES:
            if keyword.lower() in tech_blob:
                best_level, reasons = self._merge(best_level, level, reason, reasons)

        # ── 3. Title rules ───────────────────────────────────────────────
        title = (probe.http_title or "").lower()
        for keyword, reason, level in TITLE_RULES:
            if keyword.lower() in title:
                best_level, reasons = self._merge(best_level, level, reason, reasons)

        # ── 4. Status code rules (lowest precedence) ─────────────────────
        if probe.http_status is not None:
            for code, reason, level in STATUS_RULES:
                if probe.http_status == code:
                    best_level, reasons = self._merge(best_level, level, reason, reasons)
                    break  # one status rule match is enough

        # ── 5. Dead hosts are always NOISE ────────────────────────────────
        if probe.probe_status.value in ("dead", "error", "not_probed"):
            best_level = InterestLevel.NOISE
            reasons    = [f"host is {probe.probe_status.value}"]

        return probe.model_copy(
            update={
                "interest_level":   best_level,
                "interest_reasons": list(dict.fromkeys(reasons)),  # deduplicate, keep order
            }
        )

    @staticmethod
    def _merge(
        current_level: InterestLevel,
        new_level:     InterestLevel,
        reason:        str,
        reasons:       List[str],
    ) -> Tuple[InterestLevel, List[str]]:
        """
        Keep the highest interest level seen so far, always accumulate reasons.
        """
        updated_reasons = reasons + [reason]
        if _LEVEL_ORDER[new_level] > _LEVEL_ORDER[current_level]:
            return new_level, updated_reasons
        return current_level, updated_reasons


# Singleton — import this directly
classifier = FingerprintClassifier()
