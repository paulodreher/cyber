“””
Arch Threat Modeler — 100% offline engine

1. OCR extracts text from image
1. Regex anonymizes sensitive data
1. Component classifier identifies architecture elements
1. Built-in STRIDE rule engine generates threats
1. Risk scorer assigns levels
   No AI API calls — all intelligence is in the rules below.
   “””

import re
import io
import base64
from dataclasses import dataclass, field
from typing import List, Dict, Tuple, Optional
from PIL import Image, ImageDraw, ImageFilter
import pytesseract

# ─────────────────────────────────────────────────────────────────────────────

# 1. ANONYMIZATION

# ─────────────────────────────────────────────────────────────────────────────

*PATTERNS = [
(“ip”,       re.compile(r’\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?).){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)(?:/\d{1,2})?\b’)),
(“url”,      re.compile(r’https?://[^\s<>”{}|\^`[]]+’)),
(“host”,     re.compile(r’\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?.)+(?:com|net|org|io|br|gov|edu|local|internal|corp|lan|dev|prod|stg|qa)\b’, re.I)),
(“email”,    re.compile(r’\b[a-zA-Z0-9.*%+-]+@[a-zA-Z0-9.-]+.[a-zA-Z]{2,}\b’)),
(“port”,     re.compile(r’\b(?:port|porta)\s*:?\s*(\d{2,5})\b’, re.I)),
(“version”,  re.compile(r’\bv?\d+.\d+(?:.\d+)*\b’)),
(“token”,    re.compile(r’\b(?:token|key|secret|password|senha|pwd|api[_-]?key)\s*[:=]\s*\S+’, re.I)),
(“company”,  re.compile(r’\b\w+\s*(?:Corp|Corporation|Inc|Ltd|LLC|SA|LTDA|S.A.?|Group|Grupo|Technologies|Tech|Solutions|Services|Systems|Digital)\b’, re.I)),
]

_LABELS = {“ip”: “IP”, “url”: “URL”, “host”: “HOST”, “email”: “EMAIL”,
“port”: “PORT”, “version”: “VER”, “token”: “REDACTED”, “company”: “COMPANY”}

def anonymize_text(text: str) -> Tuple[str, Dict[str, str]]:
mapping: Dict[str, str] = {}
counters: Dict[str, int] = {}

```
def replace(kind: str, original: str) -> str:
    if original in mapping:
        return mapping[original]
    counters[kind] = counters.get(kind, 0) + 1
    label = f"{_LABELS[kind]}-{counters[kind]:03d}"
    mapping[original] = label
    return label

for kind, pattern in _PATTERNS:
    def sub(m, k=kind): return replace(k, m.group())
    text = pattern.sub(sub, text)

return text, mapping
```

def anonymize_image(image_bytes: bytes) -> Tuple[bytes, str, Dict[str, str]]:
img = Image.open(io.BytesIO(image_bytes)).convert(“RGB”)
w, h = img.size

```
ocr_data = pytesseract.image_to_data(img, output_type=pytesseract.Output.DICT)
full_text = pytesseract.image_to_string(img)
clean_text, mapping = anonymize_text(full_text)

anon_img = img.copy()
all_pats = [p for _, p in _PATTERNS]
n = len(ocr_data["text"])
for i in range(n):
    word = ocr_data["text"][i].strip()
    if not word:
        continue
    if any(p.search(word) for p in all_pats):
        x, y = ocr_data["left"][i], ocr_data["top"][i]
        bw, bh = ocr_data["width"][i], ocr_data["height"][i]
        pad = 4
        x1, y1 = max(0, x - pad), max(0, y - pad)
        x2, y2 = min(w, x + bw + pad), min(h, y + bh + pad)
        bar = Image.new("RGB", (x2 - x1, y2 - y1), (20, 20, 20))
        anon_img.paste(bar, (x1, y1))

buf = io.BytesIO()
anon_img.save(buf, format="PNG")
return buf.getvalue(), clean_text, mapping
```

# ─────────────────────────────────────────────────────────────────────────────

# 2. COMPONENT CLASSIFIER

# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class Component:
name: str
category: str          # e.g. “web”, “database”, “auth”, …
tags: List[str]        # fine-grained tags used by rule engine
description: str

# Each entry: (category, tags, description, keywords_regex)

_COMPONENT_RULES = [
(“load_balancer”,   [“network”, “ingress”, “lb”],
“Load Balancer / Reverse Proxy”,
re.compile(r’\b(nginx|haproxy|traefik|alb|elb|nlb|load.?balanc|reverse.?proxy|api.?gateway|gateway)\b’, re.I)),

```
("web_server",      ["web", "http", "public"],
 "Web / Application Server",
 re.compile(r'\b(apache|tomcat|iis|express|django|flask|spring|web.?server|app.?server|frontend|react|angular|vue)\b', re.I)),

("api",             ["api", "http", "rest", "grpc"],
 "API Service",
 re.compile(r'\b(api|rest|graphql|grpc|microservice|micro.?service|endpoint|swagger|openapi)\b', re.I)),

("database_sql",    ["database", "sql", "storage", "persistence"],
 "Relational Database",
 re.compile(r'\b(mysql|postgres|postgresql|mariadb|mssql|oracle|sql.?server|sqlite|rds|aurora|database|db)\b', re.I)),

("database_nosql",  ["database", "nosql", "storage"],
 "NoSQL / Document Database",
 re.compile(r'\b(mongo|mongodb|cassandra|dynamodb|couchdb|firestore|elasticsearch|opensearch)\b', re.I)),

("cache",           ["cache", "memory", "fast_store"],
 "Cache / In-Memory Store",
 re.compile(r'\b(redis|memcached|elasticache|cache|caching)\b', re.I)),

("message_queue",   ["async", "queue", "broker", "event"],
 "Message Queue / Event Broker",
 re.compile(r'\b(kafka|rabbitmq|activemq|sqs|sns|pubsub|nats|event.?bus|message.?queue|mq|broker)\b', re.I)),

("auth",            ["auth", "identity", "iam", "sso"],
 "Authentication / Identity Service",
 re.compile(r'\b(oauth|oidc|jwt|saml|ldap|active.?directory|keycloak|auth0|cognito|okta|sso|iam|identity|auth|login)\b', re.I)),

("cdn",             ["cdn", "edge", "static", "public"],
 "CDN / Edge Cache",
 re.compile(r'\b(cloudfront|cdn|edge|akamai|fastly|cloudflare)\b', re.I)),

("storage_blob",    ["storage", "blob", "files"],
 "Object / Blob Storage",
 re.compile(r'\b(s3|blob|gcs|minio|object.?storage|storage.?bucket|file.?storage)\b', re.I)),

("container_orch",  ["k8s", "container", "orchestration"],
 "Container Orchestration",
 re.compile(r'\b(kubernetes|k8s|eks|aks|gke|openshift|docker.?swarm|helm|pod|namespace)\b', re.I)),

("container",       ["container", "docker"],
 "Container / Docker",
 re.compile(r'\b(docker|container|image|dockerfile)\b', re.I)),

("vpn_firewall",    ["network", "firewall", "perimeter", "vpn"],
 "VPN / Firewall / Network Security",
 re.compile(r'\b(vpn|firewall|fw|waf|dmz|ipsec|wireguard|openvpn|security.?group|nacl|acl|perimeter)\b', re.I)),

("monitoring",      ["observability", "logging", "monitoring"],
 "Monitoring / Observability",
 re.compile(r'\b(prometheus|grafana|datadog|splunk|elk|logstash|kibana|cloudwatch|newrelic|dynatrace|jaeger|zipkin|monitor|logging|observab)\b', re.I)),

("ci_cd",           ["cicd", "pipeline", "devops"],
 "CI/CD Pipeline",
 re.compile(r'\b(jenkins|gitlab.?ci|github.?actions|circleci|travis|pipeline|cicd|ci/cd|argocd|flux)\b', re.I)),

("secret_manager",  ["secrets", "vault", "credentials"],
 "Secrets / Vault",
 re.compile(r'\b(vault|secrets.?manager|parameter.?store|aws.?secrets|azure.?keyvault|gcp.?secret)\b', re.I)),

("cloud_provider",  ["cloud", "managed"],
 "Cloud Provider Services",
 re.compile(r'\b(aws|azure|gcp|google.?cloud|amazon|ec2|lambda|fargate|cloudrun|azure.?functions)\b', re.I)),

("user_client",     ["user", "external", "browser"],
 "End User / Client",
 re.compile(r'\b(user|client|browser|mobile|app|usu.rio|cliente|frontend|web.?app|spa)\b', re.I)),

("third_party",     ["external", "third_party", "integration"],
 "Third-Party / External Service",
 re.compile(r'\b(third.?party|external|integration|webhook|payment|stripe|paypal|sendgrid|twilio|sms|smtp)\b', re.I)),

("network_generic", ["network", "switch", "router"],
 "Network Device",
 re.compile(r'\b(switch|router|hub|vlan|subnet|network|lan|wan|dmz)\b', re.I)),
```

]

def classify_components(text: str) -> List[Component]:
found: Dict[str, Component] = {}
text_lower = text.lower()
for category, tags, description, pattern in _COMPONENT_RULES:
matches = pattern.findall(text)
if matches:
# Use the most specific/first match as name
representative = matches[0] if isinstance(matches[0], str) else matches[0][0]
key = category
if key not in found:
found[key] = Component(
name=representative.strip(),
category=category,
tags=tags,
description=description
)
return list(found.values())

# ─────────────────────────────────────────────────────────────────────────────

# 3. BUILT-IN STRIDE RULE ENGINE

# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class Threat:
stride_category: str   # S T R I D E
component: str
threat: str
risk: str              # low / medium / high / critical
mitigation: str
cwe: Optional[str] = None
reference: Optional[str] = None

# risk escalation based on tag combos

def _risk(base: str, escalate: bool) -> str:
order = [“low”, “medium”, “high”, “critical”]
idx = order.index(base)
if escalate and idx < 3:
idx += 1
return order[idx]

def _has(comp: Component, *tags) -> bool:
return any(t in comp.tags for t in tags)

def _generate_threats(components: List[Component]) -> List[Threat]:
threats: List[Threat] = []
cats = {c.category for c in components}
tags_all = {t for c in components for t in c.tags}

```
has_auth     = "auth" in cats
has_public   = "public" in tags_all or "web" in tags_all or "cdn" in tags_all
has_db       = "database_sql" in cats or "database_nosql" in cats
has_queue    = "message_queue" in cats
has_cache    = "cache" in cats
has_k8s      = "container_orch" in cats
has_secrets  = "secret_manager" in cats
has_vpn      = "vpn_firewall" in cats
has_external = "third_party" in cats or "external" in tags_all
has_monitor  = "monitoring" in cats
has_cicd     = "ci_cd" in cats
has_api      = "api" in cats

for comp in components:
    name = comp.description

    # ── SPOOFING ──────────────────────────────────────────────────────
    if _has(comp, "api", "http", "rest"):
        threats.append(Threat("Spoofing", name,
            "API requests may be forged by unauthenticated clients",
            _risk("high", not has_auth),
            "Enforce mutual TLS (mTLS) or signed JWT on every API endpoint; reject unsigned requests at the gateway.",
            "CWE-287", "OWASP API1:2023"))

    if _has(comp, "user", "browser", "external"):
        threats.append(Threat("Spoofing", name,
            "Session or identity token can be stolen and replayed (session hijacking)",
            "high",
            "Use HttpOnly + Secure cookies, short-lived tokens, device fingerprinting, and enforce re-authentication for sensitive actions.",
            "CWE-384", "OWASP A07:2021"))

    if _has(comp, "auth", "sso", "identity"):
        threats.append(Threat("Spoofing", name,
            "Credential stuffing or brute-force on authentication endpoint",
            "critical",
            "Enforce MFA, account lockout after N failures, CAPTCHA, and monitor for credential-stuffing patterns.",
            "CWE-307", "NIST SP 800-63B"))

    if _has(comp, "queue", "broker", "event"):
        threats.append(Threat("Spoofing", name,
            "Rogue producer can inject malicious messages into the queue",
            "high",
            "Authenticate producers with client certificates or signed payloads; validate message schema before processing.",
            "CWE-290"))

    if _has(comp, "network", "firewall", "vpn"):
        threats.append(Threat("Spoofing", name,
            "IP spoofing or ARP poisoning on the internal network segment",
            "medium",
            "Enable ingress/egress filtering (BCP38), use dynamic ARP inspection, and segment the network with VLANs.",
            "CWE-293"))

    # ── TAMPERING ─────────────────────────────────────────────────────
    if _has(comp, "database", "sql", "nosql", "persistence"):
        threats.append(Threat("Tampering", name,
            "SQL/NoSQL injection allowing unauthorized data modification",
            "critical",
            "Use parameterized queries / ODM, enforce least-privilege DB accounts, and apply WAF rules for injection patterns.",
            "CWE-89", "OWASP A03:2021"))
        threats.append(Threat("Tampering", name,
            "Direct database access bypassing application logic",
            _risk("high", not has_vpn),
            "Place DB in a private subnet with no public ingress; allow connections only from the application tier via security groups.",
            "CWE-284"))

    if _has(comp, "storage", "blob", "files"):
        threats.append(Threat("Tampering", name,
            "Unrestricted file upload enabling malicious content injection",
            "high",
            "Validate MIME type, extension, and file content server-side; store uploads outside the web root; scan with antivirus.",
            "CWE-434", "OWASP A05:2021"))

    if _has(comp, "api", "http"):
        threats.append(Threat("Tampering", name,
            "Man-in-the-middle attack allows payload modification in transit",
            _risk("high", not has_vpn),
            "Enforce TLS 1.2+ everywhere; use HSTS with preloading; pin certificates for internal service calls.",
            "CWE-319"))

    if _has(comp, "queue", "async"):
        threats.append(Threat("Tampering", name,
            "Message integrity not verified — attacker modifies event payload",
            "medium",
            "Sign messages with HMAC or asymmetric keys; consumers must verify signature before processing.",
            "CWE-345"))

    if _has(comp, "cicd", "pipeline"):
        threats.append(Threat("Tampering", name,
            "Supply chain attack: malicious dependency or tampered build artifact",
            "critical",
            "Pin dependency versions, verify checksums/SBOMs, use private artifact registries, and enforce signed commits.",
            "CWE-494", "SLSA L2+"))

    if _has(comp, "container", "k8s"):
        threats.append(Threat("Tampering", name,
            "Container image substitution or registry poisoning",
            "high",
            "Use image signing (Cosign/Notary), enforce admission controllers to reject unsigned images, scan images in CI.",
            "CWE-494"))

    # ── REPUDIATION ───────────────────────────────────────────────────
    if _has(comp, "api", "http", "rest"):
        threats.append(Threat("Repudiation", name,
            "No tamper-evident audit trail for API calls — actions cannot be attributed",
            _risk("medium", not has_monitor),
            "Log every request with timestamp, caller identity, input hash, and response code to an append-only log store.",
            "CWE-778"))

    if _has(comp, "auth", "identity"):
        threats.append(Threat("Repudiation", name,
            "Authentication events (login, logout, failures) not logged — attacks go undetected",
            _risk("high", not has_monitor),
            "Forward auth events to a SIEM; include user, IP, device, and result; alert on anomalous patterns.",
            "CWE-223"))

    if _has(comp, "database", "sql", "nosql"):
        threats.append(Threat("Repudiation", name,
            "Database mutations have no audit log — unauthorized changes undetectable",
            "medium",
            "Enable DB audit logging for DDL and DML; ship logs to an immutable log aggregator.",
            "CWE-778"))

    if _has(comp, "queue", "broker"):
        threats.append(Threat("Repudiation", name,
            "Message consumption cannot be proven — consumer may deny processing an event",
            "low",
            "Use idempotent consumers with delivery receipts; store processed message IDs in a durable store.",
            "CWE-778"))

    # ── INFORMATION DISCLOSURE ────────────────────────────────────────
    if _has(comp, "web", "public", "cdn", "http"):
        threats.append(Threat("Information Disclosure", name,
            "Verbose error messages expose stack traces, versions, or internal paths",
            "medium",
            "Return generic error messages to clients; log details server-side only; remove Server/X-Powered-By headers.",
            "CWE-209", "OWASP A05:2021"))
        threats.append(Threat("Information Disclosure", name,
            "Sensitive data exposed in browser cache or client-side storage",
            "medium",
            "Set Cache-Control: no-store for sensitive responses; never store secrets in localStorage or URL parameters.",
            "CWE-525"))

    if _has(comp, "database", "sql", "nosql", "persistence"):
        threats.append(Threat("Information Disclosure", name,
            "Sensitive data stored in plaintext (PII, credentials, payment data)",
            "critical",
            "Encrypt sensitive columns (AES-256); use transparent data encryption (TDE) at rest; hash passwords with bcrypt/argon2.",
            "CWE-312", "OWASP A02:2021"))

    if _has(comp, "cache", "memory"):
        threats.append(Threat("Information Disclosure", name,
            "Cache poisoning or unauthorized cache read exposes other users' data",
            "high",
            "Namespace cache keys per user/session; disable debug commands (FLUSHALL) in production; enable TLS on Redis.",
            "CWE-524"))

    if _has(comp, "log", "monitoring", "observability"):
        threats.append(Threat("Information Disclosure", name,
            "Logs contain sensitive data (tokens, PII, passwords) shipped to external systems",
            "high",
            "Scrub/mask sensitive fields before logging; apply log-level controls; restrict log access with RBAC.",
            "CWE-532"))

    if _has(comp, "secrets", "vault", "credentials"):
        threats.append(Threat("Information Disclosure", name,
            "Secrets leaked via environment variables, logs, or misconfigured vault policies",
            "critical",
            "Use dynamic secrets with short TTLs; audit vault access; never log secret values; rotate on suspected exposure.",
            "CWE-798"))

    if _has(comp, "api") and has_external:
        threats.append(Threat("Information Disclosure", name,
            "SSRF allows attacker to reach internal metadata endpoints (e.g. AWS IMDSv1)",
            "high",
            "Validate and whitelist outbound URLs; use IMDSv2 with session tokens; block 169.254.169.254 at network level.",
            "CWE-918", "OWASP A10:2021"))

    # ── DENIAL OF SERVICE ─────────────────────────────────────────────
    if _has(comp, "web", "public", "cdn", "ingress", "lb"):
        threats.append(Threat("Denial of Service", name,
            "Volumetric DDoS attack overwhelms public-facing endpoint",
            "high",
            "Place CDN/WAF in front of origin; enable rate limiting and geo-blocking; use auto-scaling groups.",
            "CWE-400"))
        threats.append(Threat("Denial of Service", name,
            "Application-layer (L7) flood or slowloris attack exhausts connection pool",
            "high",
            "Configure connection timeouts, max request size limits, and request-rate throttling per IP/user.",
            "CWE-400"))

    if _has(comp, "database", "sql", "nosql"):
        threats.append(Threat("Denial of Service", name,
            "Expensive query or missing index causes database resource exhaustion",
            "medium",
            "Enforce query timeouts, connection pool limits; use read replicas for analytics; implement circuit breakers.",
            "CWE-400"))

    if _has(comp, "queue", "broker", "async"):
        threats.append(Threat("Denial of Service", name,
            "Queue flooding / poison messages cause consumer starvation or infinite retry loops",
            "medium",
            "Set message TTL, max delivery attempts, and dead-letter queues; monitor queue depth with alerts.",
            "CWE-400"))

    if _has(comp, "cache"):
        threats.append(Threat("Denial of Service", name,
            "Cache stampede: simultaneous cache misses overload the database",
            "medium",
            "Use probabilistic early expiration or mutex locking (dog-pile protection); pre-warm cache on deployment.",
            "CWE-400"))

    if _has(comp, "k8s", "container_orch"):
        threats.append(Threat("Denial of Service", name,
            "Resource exhaustion: runaway container consumes all node CPU/memory",
            "high",
            "Define resource requests and limits (requests/limits) on all pods; use horizontal pod autoscaler and PodDisruptionBudgets.",
            "CWE-400"))

    if _has(comp, "api"):
        threats.append(Threat("Denial of Service", name,
            "Missing API rate limiting allows a single client to exhaust backend resources",
            _risk("high", not has_auth),
            "Implement per-client rate limits (token bucket/leaky bucket) at the gateway; return 429 with Retry-After header.",
            "CWE-770", "OWASP API4:2023"))

    # ── ELEVATION OF PRIVILEGE ────────────────────────────────────────
    if _has(comp, "api", "http", "rest"):
        threats.append(Threat("Elevation of Privilege", name,
            "Broken object-level authorization (BOLA/IDOR): user accesses other users' resources",
            "critical",
            "Validate resource ownership on every request server-side; never trust user-supplied IDs alone; use opaque resource handles.",
            "CWE-639", "OWASP API1:2023"))
        threats.append(Threat("Elevation of Privilege", name,
            "Broken function-level authorization: unprivileged user reaches admin endpoints",
            "critical",
            "Enforce RBAC/ABAC at the API layer; deny by default; test with unprivileged tokens in CI.",
            "CWE-862", "OWASP API5:2023"))

    if _has(comp, "k8s", "container_orch"):
        threats.append(Threat("Elevation of Privilege", name,
            "Privileged container or hostPath mount allows container escape to host node",
            "critical",
            "Enforce PodSecurityAdmission (restricted profile); prohibit privileged containers and hostPath; use seccomp/AppArmor profiles.",
            "CWE-269", "CIS Kubernetes Benchmark"))
        threats.append(Threat("Elevation of Privilege", name,
            "Over-permissive ServiceAccount allows lateral movement across namespaces",
            "high",
            "Apply least-privilege RBAC to ServiceAccounts; disable auto-mount of service account tokens; use Workload Identity.",
            "CWE-250"))

    if _has(comp, "cicd", "pipeline"):
        threats.append(Threat("Elevation of Privilege", name,
            "CI/CD pipeline has write access to production — compromised pipeline = full prod access",
            "critical",
            "Separate CI (build) and CD (deploy) roles; require manual approval for prod deployments; use short-lived deploy tokens.",
            "CWE-250", "SLSA"))

    if _has(comp, "secrets", "vault"):
        threats.append(Threat("Elevation of Privilege", name,
            "Overly broad vault policy grants access to secrets beyond service's scope",
            "high",
            "Apply least-privilege vault policies per service; use namespaces/secret engines with scoped tokens.",
            "CWE-269"))

    if _has(comp, "cloud", "managed"):
        threats.append(Threat("Elevation of Privilege", name,
            "IAM role or managed identity with wildcard permissions enables privilege escalation",
            "critical",
            "Apply least-privilege IAM policies; ban Action:* Resource:*; enable AWS SCPs / Azure Policy guardrails.",
            "CWE-269", "CSA CCM IAM-02"))

    if _has(comp, "network", "firewall", "vpn"):
        threats.append(Threat("Elevation of Privilege", name,
            "Network misconfiguration allows lateral movement between security zones",
            _risk("high", not has_vpn),
            "Implement micro-segmentation; apply zero-trust network policies; log and alert on unexpected east-west traffic.",
            "CWE-284"))

# ── Cross-cutting threats (architectural level) ───────────────────────
if has_public and not has_auth:
    threats.append(Threat("Spoofing", "Architecture",
        "Public-facing services detected with no authentication layer identified",
        "critical",
        "Add an authentication/authorization layer (OAuth2, API keys, mTLS) in front of all public endpoints.",
        "CWE-306"))

if has_db and not has_vpn:
    threats.append(Threat("Information Disclosure", "Architecture",
        "Database may be reachable without network isolation (no VPN/firewall detected)",
        "critical",
        "Isolate all data stores in private subnets; restrict ingress to application-tier IPs only.",
        "CWE-284"))

if has_cicd and not has_secrets:
    threats.append(Threat("Information Disclosure", "CI/CD Pipeline",
        "No secrets manager detected — credentials likely hardcoded or in environment variables",
        "high",
        "Integrate a secrets manager (Vault, AWS Secrets Manager); rotate all secrets; scan repos for leaked credentials.",
        "CWE-798"))

if not has_monitor:
    threats.append(Threat("Repudiation", "Architecture",
        "No monitoring/observability component detected — incidents and attacks may go unnoticed",
        "high",
        "Deploy a centralized logging + alerting stack; set up anomaly detection and on-call escalation.",
        "CWE-778"))

return threats
```

# ─────────────────────────────────────────────────────────────────────────────

# 4. RISK SCORER

# ─────────────────────────────────────────────────────────────────────────────

def overall_risk(threats: List[Threat]) -> str:
counts = {“critical”: 0, “high”: 0, “medium”: 0, “low”: 0}
for t in threats:
counts[t.risk] = counts.get(t.risk, 0) + 1
if counts[“critical”] >= 1:
return “critical”
if counts[“high”] >= 3:
return “high”
if counts[“high”] >= 1 or counts[“medium”] >= 5:
return “medium”
return “low”

# ─────────────────────────────────────────────────────────────────────────────

# 5. TOP RECOMMENDATIONS  (derived from threats, not AI)

# ─────────────────────────────────────────────────────────────────────────────

def top_recommendations(threats: List[Threat], n: int = 8) -> List[str]:
# Prioritize by risk level, then deduplicate mitigations
order = {“critical”: 0, “high”: 1, “medium”: 2, “low”: 3}
sorted_threats = sorted(threats, key=lambda t: order.get(t.risk, 9))
seen, recs = set(), []
for t in sorted_threats:
key = t.mitigation[:60]
if key not in seen:
seen.add(key)
recs.append(f”[{t.risk.upper()}] {t.mitigation}”)
if len(recs) >= n:
break
return recs

# ─────────────────────────────────────────────────────────────────────────────

# 6. MAIN PIPELINE

# ─────────────────────────────────────────────────────────────────────────────

def analyze(image_bytes: bytes) -> dict:
anon_bytes, clean_text, mapping = anonymize_image(image_bytes)
components = classify_components(clean_text)

```
# Fallback: if OCR found nothing useful, return a minimal generic analysis
if not components:
    components = [Component("Unknown", "generic", ["network", "http"], "Unidentified Component")]

threats = _generate_threats(components)
risk = overall_risk(threats)
recs = top_recommendations(threats)

stride_map: Dict[str, List[dict]] = {
    "Spoofing": [], "Tampering": [], "Repudiation": [],
    "Information Disclosure": [], "Denial of Service": [],
    "Elevation of Privilege": []
}
for t in threats:
    stride_map[t.stride_category].append({
        "component": t.component,
        "threat": t.threat,
        "risk": t.risk,
        "mitigation": t.mitigation,
        "cwe": t.cwe or "",
        "reference": t.reference or "",
    })

return {
    "anonymized_image_bytes": anon_bytes,
    "mapping": mapping,
    "components": [{"name": c.name, "category": c.category, "description": c.description} for c in components],
    "stride": stride_map,
    "overall_risk": risk,
    "recommendations": recs,
    "threat_count": len(threats),
    "clean_text_sample": clean_text[:300],
}
```
