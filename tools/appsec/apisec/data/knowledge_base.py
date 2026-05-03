"""
Keyword-based Q&A knowledge base for the OWASP API Security chatbot.
No external API required — pure keyword matching with scored ranking.
"""

from __future__ import annotations
import re
from typing import List, Tuple


# ---------------------------------------------------------------------------
# Q&A entries: each has a list of trigger keywords and a markdown answer.
# ---------------------------------------------------------------------------
QA_ENTRIES: List[dict] = [
    # ── General OWASP ──────────────────────────────────────────────────────
    {
        "keywords": ["owasp", "top 10", "api security", "list", "overview", "what is"],
        "question": "What is the OWASP API Security Top 10?",
        "answer": (
            "The **OWASP API Security Top 10** is a list of the most critical API security "
            "risks, published by the Open Web Application Security Project (OWASP). "
            "The 2023 edition covers:\n\n"
            "| # | Name |\n"
            "|---|------|\n"
            "| API1 | Broken Object Level Authorization (BOLA) |\n"
            "| API2 | Broken Authentication |\n"
            "| API3 | Broken Object Property Level Authorization |\n"
            "| API4 | Unrestricted Resource Consumption |\n"
            "| API5 | Broken Function Level Authorization |\n"
            "| API6 | Unrestricted Access to Sensitive Business Flows |\n"
            "| API7 | Server Side Request Forgery (SSRF) |\n"
            "| API8 | Security Misconfiguration |\n"
            "| API9 | Improper Inventory Management |\n"
            "| API10 | Unsafe Consumption of APIs |\n\n"
            "📖 Full list: https://owasp.org/API-Security/editions/2023/en/0x00-header/"
        ),
    },
    # ── BOLA / IDOR ────────────────────────────────────────────────────────
    {
        "keywords": ["bola", "idor", "object level", "authorization", "api1", "order id",
                     "broken object", "horizontal", "privilege", "enumerate"],
        "question": "What is BOLA (Broken Object Level Authorization)?",
        "answer": (
            "**BOLA (API1)** occurs when an API endpoint accepts an object ID from the "
            "client but does not verify that the authenticated user has permission to "
            "access that specific object.\n\n"
            "**Quick fix:** Always filter database queries by both the object ID **and** "
            "the authenticated user's ID:\n\n"
            "```python\n"
            "# Python / SQLAlchemy\n"
            "order = Order.query.filter_by(id=order_id, user_id=current_user.id).first()\n"
            "```\n\n"
            "**Risk level:** Critical — most common API vulnerability.\n\n"
            "📖 https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/"
        ),
    },
    # ── Authentication ─────────────────────────────────────────────────────
    {
        "keywords": ["authentication", "jwt", "token", "login", "password", "brute force",
                     "credential", "api2", "broken auth", "none algorithm", "weak secret"],
        "question": "What is Broken Authentication (API2)?",
        "answer": (
            "**Broken Authentication (API2)** includes:\n\n"
            "- Weak or hardcoded JWT secrets\n"
            "- Missing token expiry\n"
            "- JWT algorithm confusion (accepting 'none')\n"
            "- No brute-force / rate-limit protection on login\n"
            "- Plain-text password storage\n\n"
            "**Key mitigations:**\n"
            "1. Use `bcrypt` / `argon2` for passwords\n"
            "2. Set JWT `exp` claim (short-lived, 15–60 min)\n"
            "3. Specify the signing algorithm explicitly: `algorithms=['HS256']`\n"
            "4. Rate-limit login endpoints (5 attempts / minute)\n"
            "5. Use secrets ≥ 256 bits from environment variables\n\n"
            "📖 https://owasp.org/API-Security/editions/2023/en/0xa2-broken-authentication/"
        ),
    },
    # ── Mass Assignment / Excessive Data Exposure ───────────────────────────
    {
        "keywords": ["mass assignment", "excessive data", "data exposure", "api3",
                     "object property", "field", "whitelist", "allowlist", "dto", "role"],
        "question": "What is Broken Object Property Level Authorization (API3)?",
        "answer": (
            "**API3** covers two related issues:\n\n"
            "**Excessive Data Exposure** — returning more fields than needed "
            "(e.g., password hashes, internal flags).\n\n"
            "**Mass Assignment** — accepting all JSON fields without an allowlist, "
            "allowing attackers to set privileged fields like `role` or `isAdmin`.\n\n"
            "**Fixes:**\n"
            "- Define an **allowlist** of fields that can be updated\n"
            "- Use **DTOs** (Data Transfer Objects) to map input to model\n"
            "- Use **response serializers** that only expose safe fields\n\n"
            "```javascript\n"
            "const ALLOWED = ['name', 'bio'];\n"
            "const updates = Object.fromEntries(\n"
            "  Object.entries(req.body).filter(([k]) => ALLOWED.includes(k))\n"
            ");\n"
            "```\n\n"
            "📖 https://owasp.org/API-Security/editions/2023/en/0xa3-broken-object-property-level-authorization/"
        ),
    },
    # ── Rate Limiting / DoS ────────────────────────────────────────────────
    {
        "keywords": ["rate limit", "dos", "denial of service", "resource", "consumption",
                     "api4", "pagination", "throttle", "flood", "scraping", "upload size"],
        "question": "How do I prevent Unrestricted Resource Consumption (API4)?",
        "answer": (
            "**API4** covers missing rate limits, unbounded pagination, and unlimited "
            "upload sizes.\n\n"
            "**Mitigations:**\n\n"
            "| Control | Implementation |\n"
            "|---------|----------------|\n"
            "| Rate limiting | `flask-limiter`, `express-rate-limit`, Nginx `limit_req` |\n"
            "| Pagination | Always cap `page_size` (e.g., max 100) |\n"
            "| Upload size | Set `Content-Length` max in your web server |\n"
            "| Query timeouts | Set DB query timeouts to prevent long-running queries |\n\n"
            "```python\n"
            "# Flask\n"
            "per_page = min(int(request.args.get('per_page', 20)), 100)\n"
            "```\n\n"
            "📖 https://owasp.org/API-Security/editions/2023/en/0xa4-unrestricted-resource-consumption/"
        ),
    },
    # ── BFLA / Function Level Auth ─────────────────────────────────────────
    {
        "keywords": ["bfla", "function level", "admin endpoint", "role", "api5",
                     "broken function", "hidden endpoint", "privilege escalation"],
        "question": "What is Broken Function Level Authorization (API5)?",
        "answer": (
            "**BFLA (API5)** happens when authentication is checked but role/permission "
            "is not — any authenticated user can call admin-only endpoints.\n\n"
            "**Red flags:**\n"
            "- Admin endpoints only protected by URL path convention (`/admin/`)\n"
            "- Middleware that checks token validity but not role claims\n\n"
            "**Fixes:**\n"
            "```python\n"
            "# Python – role decorator\n"
            "def admin_required(fn):\n"
            "    @wraps(fn)\n"
            "    @jwt_required()\n"
            "    def wrapper(*args, **kwargs):\n"
            "        if get_jwt().get('role') != 'admin':\n"
            "            return jsonify({'error': 'Forbidden'}), 403\n"
            "        return fn(*args, **kwargs)\n"
            "    return wrapper\n"
            "```\n\n"
            "```java\n"
            "// Spring Boot\n"
            "@PreAuthorize(\"hasRole('ADMIN')\")\n"
            "@DeleteMapping(\"/api/v1/admin/users\")\n"
            "```\n\n"
            "📖 https://owasp.org/API-Security/editions/2023/en/0xa5-broken-function-level-authorization/"
        ),
    },
    # ── Business Logic ─────────────────────────────────────────────────────
    {
        "keywords": ["business logic", "bot", "automation", "api6", "scalping",
                     "referral fraud", "captcha", "purchase limit", "sensitive flow"],
        "question": "How do I protect sensitive business flows (API6)?",
        "answer": (
            "**API6** targets flows like purchasing, voting, and referrals that bots "
            "can abuse at scale.\n\n"
            "**Defenses:**\n"
            "- **Rate limiting** per user/IP on critical actions\n"
            "- **Per-user business rules** (max 2 items per customer)\n"
            "- **CAPTCHA** (reCAPTCHA v3 / hCaptcha) for account creation and checkout\n"
            "- **Device fingerprinting** to detect bot patterns\n"
            "- **Idempotency keys** to prevent duplicate operations\n"
            "- **Distributed locks** (Redis `SETNX`) to prevent race conditions\n\n"
            "📖 https://owasp.org/API-Security/editions/2023/en/0xa6-unrestricted-access-to-sensitive-business-flows/"
        ),
    },
    # ── SSRF ───────────────────────────────────────────────────────────────
    {
        "keywords": ["ssrf", "server side request forgery", "api7", "metadata",
                     "internal", "169.254", "url fetch", "webhook url", "redirect"],
        "question": "What is SSRF and how do I prevent it?",
        "answer": (
            "**SSRF (API7)** occurs when an API fetches a URL supplied by the user "
            "without validation. Attackers point the URL at:\n\n"
            "- AWS metadata: `http://169.254.169.254/latest/meta-data/iam/...`\n"
            "- Internal services: `http://10.0.0.5:8080/admin`\n"
            "- Local filesystem: `file:///etc/passwd`\n\n"
            "**Prevention:**\n"
            "1. **Allowlist** permitted schemes (`https` only) and hostnames\n"
            "2. **Resolve and block** private/loopback IP ranges after DNS lookup\n"
            "3. **Disable redirects** (`allow_redirects=False`)\n"
            "4. Use **IMDSv2** (AWS) which requires a session token\n\n"
            "```python\n"
            "import ipaddress, socket\n"
            "ip = ipaddress.ip_address(socket.gethostbyname(host))\n"
            "if ip.is_private or ip.is_loopback:\n"
            "    raise ValueError('Private IPs not allowed')\n"
            "```\n\n"
            "📖 https://owasp.org/API-Security/editions/2023/en/0xa7-server-side-request-forgery/"
        ),
    },
    # ── Security Misconfiguration ───────────────────────────────────────────
    {
        "keywords": ["misconfiguration", "cors", "debug", "api8", "stack trace",
                     "actuator", "headers", "hsts", "helmet", "talisman", "error message"],
        "question": "What counts as Security Misconfiguration in APIs (API8)?",
        "answer": (
            "**API8** covers a broad set of hardening failures:\n\n"
            "| Issue | Fix |\n"
            "|-------|-----|\n"
            "| Debug mode in production | `DEBUG=False`, `APP_ENV=production` |\n"
            "| Stack traces in responses | Return generic `500 Internal Server Error` |\n"
            "| Permissive CORS | Specify exact origins, not `*` |\n"
            "| Missing security headers | Use `helmet` (Node) / `flask-talisman` (Python) |\n"
            "| Open actuator endpoints | Restrict to health-only or internal network |\n"
            "| Unnecessary HTTP methods | Only enable GET/POST/PUT/DELETE as required |\n\n"
            "📖 https://owasp.org/API-Security/editions/2023/en/0xa8-security-misconfiguration/"
        ),
    },
    # ── Inventory Management ────────────────────────────────────────────────
    {
        "keywords": ["inventory", "shadow api", "deprecated", "old version", "api9",
                     "versioning", "microservice", "documentation", "openapi", "swagger",
                     "forgotten endpoint", "debug endpoint"],
        "question": "What is Improper Inventory Management (API9)?",
        "answer": (
            "**API9** happens when you lose track of what API endpoints exist — "
            "old versions, debug routes, and undocumented microservices become "
            "an unmonitored attack surface.\n\n"
            "**Best practices:**\n"
            "- Maintain an **OpenAPI/Swagger spec** as the single source of truth\n"
            "- Use a **gateway** (Kong, AWS API GW) that only routes known endpoints\n"
            "- Implement a **deprecation lifecycle**: announce → sunset header → remove\n"
            "- Gate debug/test routes with environment checks or build flags\n"
            "- Run **API discovery tools** (e.g., `nuclei`, `kiterunner`) in CI/CD\n\n"
            "📖 https://owasp.org/API-Security/editions/2023/en/0xa9-improper-inventory-management/"
        ),
    },
    # ── Unsafe API Consumption ──────────────────────────────────────────────
    {
        "keywords": ["third party", "api10", "unsafe consumption", "webhook", "hmac",
                     "signature", "tls verify", "external api", "supply chain", "validation"],
        "question": "How do I safely consume third-party APIs (API10)?",
        "answer": (
            "**API10** covers risks introduced by trusting upstream APIs blindly.\n\n"
            "**Checklist:**\n"
            "- ✅ Always set **timeouts** on external HTTP calls\n"
            "- ✅ **Verify TLS certificates** (`verify=True` — never `InsecureSkipVerify`)\n"
            "- ✅ **Validate and sanitize** all data received from third-party APIs\n"
            "- ✅ **Limit response size** to prevent memory exhaustion\n"
            "- ✅ Verify **webhook signatures** (HMAC-SHA256) before processing\n"
            "- ✅ Use a **schema validator** (Pydantic, Joi, JSON Schema) on responses\n\n"
            "```python\n"
            "# Verify webhook HMAC\n"
            "import hmac, hashlib\n"
            "expected = hmac.new(secret, payload, hashlib.sha256).hexdigest()\n"
            "if not hmac.compare_digest(expected, received_sig):\n"
            "    return 401\n"
            "```\n\n"
            "📖 https://owasp.org/API-Security/editions/2023/en/0xaa-unsafe-consumption-of-apis/"
        ),
    },
    # ── Input Validation ────────────────────────────────────────────────────
    {
        "keywords": ["input validation", "sql injection", "injection", "sanitize",
                     "parameterize", "prepared statement", "xss", "cross site"],
        "question": "How do I prevent injection attacks in APIs?",
        "answer": (
            "**Injection** (SQLi, XSS, command injection) remains dangerous in APIs:\n\n"
            "**SQL Injection:**\n"
            "```python\n"
            "# BAD\n"
            "db.execute(f\"SELECT * FROM users WHERE id = {user_id}\")\n\n"
            "# GOOD — parameterized query\n"
            "db.execute(\"SELECT * FROM users WHERE id = %s\", (user_id,))\n"
            "```\n\n"
            "**XSS (stored via API):**\n"
            "```javascript\n"
            "// Sanitize before storing / returning as HTML\n"
            "const clean = DOMPurify.sanitize(userInput);\n"
            "```\n\n"
            "**General rules:**\n"
            "- Validate type, length, format for every input field\n"
            "- Use ORM parameterized queries — never string concatenation\n"
            "- Encode output for the rendering context (HTML, JSON, SQL)\n"
            "- Apply allowlist input validation where possible\n\n"
            "📖 https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html"
        ),
    },
    # ── Encryption / TLS ────────────────────────────────────────────────────
    {
        "keywords": ["encryption", "tls", "https", "certificate", "ssl", "transport",
                     "data in transit", "data at rest", "aes", "cipher"],
        "question": "What encryption should APIs use?",
        "answer": (
            "**Transport Layer:**\n"
            "- Enforce **TLS 1.2+** (disable TLS 1.0, 1.1, SSL 3.0)\n"
            "- Use **HSTS** (`Strict-Transport-Security: max-age=31536000; includeSubDomains`)\n"
            "- Redirect all HTTP to HTTPS\n\n"
            "**Data at Rest:**\n"
            "- Encrypt sensitive DB columns with **AES-256-GCM**\n"
            "- Store passwords with **bcrypt** / **argon2id** (never MD5/SHA1)\n"
            "- Encrypt backups and log files containing PII\n\n"
            "**Secrets Management:**\n"
            "- Use **Vault**, **AWS Secrets Manager**, or **environment variables**\n"
            "- Never commit secrets to source control\n\n"
            "📖 https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html"
        ),
    },
    # ── ASVS ───────────────────────────────────────────────────────────────
    {
        "keywords": ["asvs", "application security verification", "verification standard",
                     "level 1", "level 2", "level 3", "compliance"],
        "question": "What is OWASP ASVS?",
        "answer": (
            "The **OWASP Application Security Verification Standard (ASVS)** is a "
            "framework of security requirements for web/API applications, organized "
            "into three assurance levels:\n\n"
            "| Level | Description | Suitable for |\n"
            "|-------|-------------|--------------|\n"
            "| L1 | Opportunistic | All apps — basic security |\n"
            "| L2 | Standard | Most apps — handles sensitive data |\n"
            "| L3 | Advanced | Critical systems — financial, healthcare |\n\n"
            "Key chapters for API security:\n"
            "- V2: Authentication\n"
            "- V4: Access Control\n"
            "- V5: Validation/Sanitization/Encoding\n"
            "- V13: API & Web Services\n"
            "- V14: Configuration\n\n"
            "📖 https://owasp.org/www-project-application-security-verification-standard/"
        ),
    },
    # ── OAuth / JWT ────────────────────────────────────────────────────────
    {
        "keywords": ["oauth", "openid", "oidc", "access token", "refresh token",
                     "pkce", "authorization code", "client credentials"],
        "question": "What OAuth 2.0 flow should APIs use?",
        "answer": (
            "**Recommended OAuth 2.0 Flows:**\n\n"
            "| Scenario | Flow |\n"
            "|----------|------|\n"
            "| User-facing web/mobile app | Authorization Code + **PKCE** |\n"
            "| Machine-to-machine | Client Credentials |\n"
            "| Never use | Implicit Flow (deprecated) |\n"
            "| Never use | Resource Owner Password Credentials |\n\n"
            "**Key security points:**\n"
            "- Use **short-lived access tokens** (15–60 min)\n"
            "- Rotate **refresh tokens** on every use (token rotation)\n"
            "- Validate `iss`, `aud`, `exp` claims in every request\n"
            "- Use asymmetric signing (RS256 / ES256) for public consumers\n\n"
            "📖 https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html"
        ),
    },
    # ── Logging / Monitoring ────────────────────────────────────────────────
    {
        "keywords": ["logging", "monitoring", "audit", "siem", "detect", "alert",
                     "intrusion", "anomaly", "log", "trace"],
        "question": "What should APIs log for security monitoring?",
        "answer": (
            "**Minimum Security Logging (OWASP ASVS V7):**\n\n"
            "- All authentication events (success, failure, lockout)\n"
            "- All authorization failures (403 responses)\n"
            "- All input validation failures (400 responses on sensitive endpoints)\n"
            "- Sensitive data access (PII, financial records)\n"
            "- Admin actions (user creation, deletion, privilege changes)\n\n"
            "**Log fields to include:**\n"
            "`timestamp`, `user_id`, `ip_address`, `endpoint`, `method`, "
            "`status_code`, `request_id`\n\n"
            "**What NOT to log:**\n"
            "- Passwords, tokens, credit card numbers, SSNs\n"
            "- Full request/response bodies (PII risk)\n\n"
            "📖 https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html"
        ),
    },
    # ── CORS ───────────────────────────────────────────────────────────────
    {
        "keywords": ["cors", "cross origin", "origin", "access control allow origin",
                     "preflight", "credentials"],
        "question": "How should I configure CORS for an API?",
        "answer": (
            "**CORS Best Practices:**\n\n"
            "- **Never** use `Access-Control-Allow-Origin: *` for credentialed APIs\n"
            "- Specify an **explicit allowlist** of trusted origins\n"
            "- Only allow the HTTP methods your API actually uses\n"
            "- Set `Access-Control-Allow-Credentials: true` only when necessary\n\n"
            "```python\n"
            "# Flask\n"
            "from flask_cors import CORS\n"
            "CORS(app, origins=['https://app.example.com'], supports_credentials=True)\n"
            "```\n\n"
            "```javascript\n"
            "// Express\n"
            "app.use(cors({\n"
            "  origin: 'https://app.example.com',\n"
            "  methods: ['GET', 'POST', 'PUT', 'DELETE'],\n"
            "  credentials: true,\n"
            "}));\n"
            "```\n\n"
            "📖 https://cheatsheetseries.owasp.org/cheatsheets/CORS_Cheat_Sheet.html"
        ),
    },
    # ── Default / Fallback ──────────────────────────────────────────────────
    {
        "keywords": ["help", "how", "what", "secure", "best practice", "tip", "guide"],
        "question": "General API security tips",
        "answer": (
            "**Top API Security Best Practices:**\n\n"
            "1. **Authenticate every endpoint** — no security by obscurity\n"
            "2. **Authorize at object level** — filter DB by user ownership\n"
            "3. **Validate all inputs** — type, length, format, range\n"
            "4. **Rate-limit all endpoints** — especially auth and search\n"
            "5. **Use HTTPS everywhere** — enforce HSTS\n"
            "6. **Log security events** — auth failures, 403s, anomalies\n"
            "7. **Keep an API inventory** — document every endpoint in OpenAPI\n"
            "8. **Scan in CI/CD** — OWASP ZAP, nuclei, semgrep\n"
            "9. **Use short-lived tokens** — expire JWTs quickly, rotate refresh tokens\n"
            "10. **Never trust third-party data** — validate and sanitize all responses\n\n"
            "Select a vulnerability in the sidebar to see detailed examples and attacks!"
        ),
    },
]


# ---------------------------------------------------------------------------
# KnowledgeBase class
# ---------------------------------------------------------------------------

class KnowledgeBase:
    """Keyword-scored Q&A engine — no external API needed."""

    def __init__(self) -> None:
        self.entries = QA_ENTRIES

    def _tokenize(self, text: str) -> List[str]:
        """Lowercase and split on non-alphanumeric characters."""
        return re.findall(r"[a-z0-9]+", text.lower())

    def _score(self, query_tokens: List[str], entry: dict) -> int:
        """Count keyword hits for an entry."""
        score = 0
        keywords = entry["keywords"]
        for qt in query_tokens:
            for kw in keywords:
                kw_tokens = self._tokenize(kw)
                if qt in kw_tokens:
                    score += 1
                elif any(qt in kwt for kwt in kw_tokens):
                    score += 0.5  # partial match
        return score

    def search(self, query: str, top_n: int = 3) -> List[dict]:
        """Return the top_n matching Q&A entries for the given query."""
        tokens = self._tokenize(query)
        if not tokens:
            return []

        scored: List[Tuple[float, dict]] = []
        for entry in self.entries:
            s = self._score(tokens, entry)
            if s > 0:
                scored.append((s, entry))

        scored.sort(key=lambda x: x[0], reverse=True)
        return [e for _, e in scored[:top_n]]

    def answer(self, query: str) -> str:
        """Return a markdown-formatted answer for the query."""
        results = self.search(query, top_n=1)
        if not results:
            return (
                "I couldn't find a specific answer for that query. "
                "Try asking about:\n\n"
                "- A specific vulnerability (e.g., 'What is BOLA?')\n"
                "- A technology (e.g., 'JWT', 'OAuth', 'CORS')\n"
                "- A control (e.g., 'rate limiting', 'input validation')\n"
                "- General topics (e.g., 'OWASP Top 10', 'ASVS')\n\n"
                "You can also select any vulnerability in the left sidebar for "
                "detailed code examples and attack simulations."
            )
        best = results[0]
        return f"### {best['question']}\n\n{best['answer']}"
