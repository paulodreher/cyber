# OWASP API Security Top 10 – 2023
# Each entry is a dict with: id, title, short_desc, risk_rating,
# vulnerable_code (dict lang→code), secure_code (dict lang→code),
# curl_attacks (list of dicts: title, command, explanation),
# propagation, references (list of dicts: title, url)

VULNERABILITIES = [
    # ─────────────────────────────────────────────────────────────────────────
    # API1:2023 – Broken Object Level Authorization
    # ─────────────────────────────────────────────────────────────────────────
    {
        "id": "API1",
        "title": "API1:2023 – Broken Object Level Authorization (BOLA / IDOR)",
        "short_desc": (
            "APIs expose endpoints that handle object identifiers. When the server "
            "fails to validate that the authenticated user has permission to access "
            "a specific object, attackers can simply substitute another object's ID "
            "to read, modify, or delete any resource."
        ),
        "risk_rating": "Critical",
        "vulnerable_code": {
            "Python (Flask)": """\
# BAD: No ownership check — any authenticated user can fetch any order
@app.route("/api/v1/orders/<int:order_id>", methods=["GET"])
@jwt_required()
def get_order(order_id):
    order = db.session.get(Order, order_id)   # ← fetches ANY order by PK
    if not order:
        return jsonify({"error": "Not found"}), 404
    return jsonify(order.to_dict())
""",
            "JavaScript (Express)": """\
// BAD: No ownership check
app.get('/api/v1/orders/:orderId', authenticate, async (req, res) => {
  const order = await Order.findById(req.params.orderId); // ← any orderId
  if (!order) return res.status(404).json({ error: 'Not found' });
  res.json(order);
});
""",
            "Java (Spring Boot)": """\
// BAD: No ownership check
@GetMapping("/api/v1/orders/{orderId}")
public ResponseEntity<Order> getOrder(@PathVariable Long orderId,
                                      Principal principal) {
    Order order = orderRepository.findById(orderId)   // ← any orderId
        .orElseThrow(() -> new NotFoundException("Order not found"));
    return ResponseEntity.ok(order);
}
""",
            "Go": """\
// BAD: No ownership check
func GetOrder(c *gin.Context) {
    id := c.Param("id")
    var order Order
    db.First(&order, id) // ← fetches any record
    c.JSON(http.StatusOK, order)
}
""",
            "PHP (Laravel)": """\
// BAD: No ownership check
public function show($orderId)
{
    $order = Order::findOrFail($orderId); // ← any orderId
    return response()->json($order);
}
""",
        },
        "secure_code": {
            "Python (Flask)": """\
# GOOD: Filter by authenticated user's ID
@app.route("/api/v1/orders/<int:order_id>", methods=["GET"])
@jwt_required()
def get_order(order_id):
    current_user_id = get_jwt_identity()
    order = Order.query.filter_by(id=order_id, user_id=current_user_id).first()
    if not order:
        return jsonify({"error": "Forbidden"}), 403   # same response — no info leak
    return jsonify(order.to_dict())
""",
            "JavaScript (Express)": """\
// GOOD: Scope query to authenticated user
app.get('/api/v1/orders/:orderId', authenticate, async (req, res) => {
  const order = await Order.findOne({
    _id: req.params.orderId,
    userId: req.user.id,   // ← ownership check
  });
  if (!order) return res.status(403).json({ error: 'Forbidden' });
  res.json(order);
});
""",
            "Java (Spring Boot)": """\
// GOOD: Include user ownership in the query
@GetMapping("/api/v1/orders/{orderId}")
public ResponseEntity<Order> getOrder(@PathVariable Long orderId,
                                      Principal principal) {
    User user = userService.findByUsername(principal.getName());
    Order order = orderRepository.findByIdAndUserId(orderId, user.getId())
        .orElseThrow(() -> new ForbiddenException("Access denied"));
    return ResponseEntity.ok(order);
}
""",
            "Go": """\
// GOOD: Add user_id filter
func GetOrder(c *gin.Context) {
    id := c.Param("id")
    userID := c.MustGet("userID").(uint)
    var order Order
    result := db.Where("id = ? AND user_id = ?", id, userID).First(&order)
    if result.Error != nil {
        c.JSON(http.StatusForbidden, gin.H{"error": "access denied"})
        return
    }
    c.JSON(http.StatusOK, order)
}
""",
            "PHP (Laravel)": """\
// GOOD: Use authenticated user scope
public function show($orderId)
{
    $order = auth()->user()->orders()->findOrFail($orderId); // ← scoped to user
    return response()->json($order);
}
""",
        },
        "curl_attacks": [
            {
                "title": "Horizontal privilege escalation — access another user's order",
                "command": (
                    "# Log in as user A, get a token\n"
                    "TOKEN=$(curl -s -X POST https://api.example.com/auth/login \\\n"
                    "  -H 'Content-Type: application/json' \\\n"
                    "  -d '{\"email\":\"attacker@evil.com\",\"password\":\"pass\"}' | jq -r .token)\n\n"
                    "# Guess / enumerate order IDs that belong to other users\n"
                    "for ID in $(seq 1000 1100); do\n"
                    "  curl -s -H \"Authorization: Bearer $TOKEN\" \\\n"
                    "       https://api.example.com/api/v1/orders/$ID\n"
                    "done"
                ),
                "explanation": (
                    "The attacker iterates through sequential IDs. "
                    "Any 200 response leaks data belonging to a different account."
                ),
            },
            {
                "title": "Delete another user's resource",
                "command": (
                    "curl -X DELETE https://api.example.com/api/v1/orders/4291 \\\n"
                    "  -H \"Authorization: Bearer $ATTACKER_TOKEN\""
                ),
                "explanation": "If the delete endpoint also lacks an ownership check, the attacker can wipe any record.",
            },
        ],
        "propagation": (
            "**Initial Access:** Attacker authenticates with a valid account.\n\n"
            "**Enumeration:** Sequential or predictable IDs (integers, short UUIDs) are "
            "iterated automatically. Tools like Burp Intruder or simple bash loops "
            "can sweep thousands of IDs in minutes.\n\n"
            "**Data Exfiltration:** PII, payment details, medical records — anything "
            "stored behind the endpoint is exposed in plain JSON responses.\n\n"
            "**Lateral Actions:** If write/delete endpoints have the same flaw, attackers "
            "can modify orders, reset passwords, or delete entire datasets.\n\n"
            "**Business Impact:** GDPR/HIPAA breach notifications, regulatory fines, "
            "reputational damage, account takeover at scale."
        ),
        "references": [
            {"title": "OWASP API1:2023 Broken Object Level Authorization", "url": "https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/"},
            {"title": "OWASP ASVS V4 – Access Control", "url": "https://owasp.org/www-project-application-security-verification-standard/"},
            {"title": "OWASP Cheat Sheet – Authorization", "url": "https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html"},
            {"title": "OWASP Proactive Controls – Enforce Access Controls", "url": "https://owasp.org/www-project-proactive-controls/"},
        ],
    },

    # ─────────────────────────────────────────────────────────────────────────
    # API2:2023 – Broken Authentication
    # ─────────────────────────────────────────────────────────────────────────
    {
        "id": "API2",
        "title": "API2:2023 – Broken Authentication",
        "short_desc": (
            "Authentication mechanisms are implemented incorrectly, allowing attackers "
            "to compromise authentication tokens or to exploit implementation flaws to "
            "assume other users' identities temporarily or permanently."
        ),
        "risk_rating": "Critical",
        "vulnerable_code": {
            "Python (Flask)": """\
# BAD: Weak JWT secret, no expiry, accepts 'none' algorithm
import jwt

SECRET = "secret"   # weak, predictable

@app.route("/api/v1/login", methods=["POST"])
def login():
    user = authenticate(request.json)
    token = jwt.encode({"sub": user.id}, SECRET, algorithm="HS256")
    return jsonify({"token": token})

@app.route("/api/v1/profile")
def profile():
    token = request.headers.get("Authorization", "").replace("Bearer ", "")
    # BAD: trusts the algorithm from the token header
    data = jwt.decode(token, SECRET, algorithms=None)  # ← allows 'none'
    ...
""",
            "JavaScript (Express)": """\
// BAD: No brute-force protection, plain-text password comparison
app.post('/api/v1/login', async (req, res) => {
  const user = await User.findOne({ email: req.body.email });
  // BAD: plain text comparison — passwords stored unhashed
  if (user && user.password === req.body.password) {
    const token = jwt.sign({ id: user._id }, 'mysecret');  // no expiry
    return res.json({ token });
  }
  res.status(401).json({ error: 'Invalid credentials' });
});
""",
            "Java (Spring Boot)": """\
// BAD: No rate limiting, weak secret
@PostMapping("/api/v1/login")
public ResponseEntity<?> login(@RequestBody LoginRequest req) {
    User user = userRepo.findByEmail(req.getEmail());
    if (user != null && user.getPassword().equals(req.getPassword())) { // plain text
        String token = Jwts.builder()
            .setSubject(user.getId().toString())
            .signWith(SignatureAlgorithm.HS256, "secret") // weak key
            .compact();                                    // no expiry
        return ResponseEntity.ok(new TokenResponse(token));
    }
    return ResponseEntity.status(401).build();
}
""",
            "Go": """\
// BAD: No token expiry, weak HMAC secret
func Login(c *gin.Context) {
    var creds Credentials
    json.NewDecoder(c.Request.Body).Decode(&creds)
    user := findUser(creds.Email)
    if user != nil && user.Password == creds.Password { // plain text
        token := jwt.New(jwt.SigningMethodHS256)
        ss, _ := token.SignedString([]byte("secret")) // weak
        c.JSON(200, gin.H{"token": ss})
    }
}
""",
            "PHP (Laravel)": """\
// BAD: No throttle middleware, no hashed passwords
public function login(Request $request)
{
    $user = User::where('email', $request->email)->first();
    if ($user && $user->password === $request->password) { // plain text
        $token = $user->createToken('api')->plainTextToken;
        return response()->json(['token' => $token]);
    }
    return response()->json(['error' => 'Unauthorized'], 401);
}
""",
        },
        "secure_code": {
            "Python (Flask)": """\
# GOOD: Strong secret from env, expiry, explicit algorithm, bcrypt
import os, bcrypt
from datetime import datetime, timedelta, timezone
import jwt

SECRET = os.environ["JWT_SECRET"]  # ≥ 256-bit random value

@app.route("/api/v1/login", methods=["POST"])
@limiter.limit("5 per minute")          # brute-force protection
def login():
    user = User.query.filter_by(email=request.json["email"]).first()
    if not user or not bcrypt.checkpw(request.json["password"].encode(), user.pw_hash):
        return jsonify({"error": "Invalid credentials"}), 401
    payload = {
        "sub": user.id,
        "exp": datetime.now(timezone.utc) + timedelta(hours=1),
        "iat": datetime.now(timezone.utc),
    }
    token = jwt.encode(payload, SECRET, algorithm="HS256")
    return jsonify({"token": token})

@app.route("/api/v1/profile")
def profile():
    token = request.headers.get("Authorization", "").replace("Bearer ", "")
    data = jwt.decode(token, SECRET, algorithms=["HS256"])  # explicit allow-list
    ...
""",
            "JavaScript (Express)": """\
// GOOD: bcrypt, token expiry, rate limiting
const bcrypt = require('bcrypt');
const rateLimit = require('express-rate-limit');

const loginLimiter = rateLimit({ windowMs: 60_000, max: 5 });

app.post('/api/v1/login', loginLimiter, async (req, res) => {
  const user = await User.findOne({ email: req.body.email });
  if (!user || !(await bcrypt.compare(req.body.password, user.passwordHash))) {
    return res.status(401).json({ error: 'Invalid credentials' });
  }
  const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, {
    expiresIn: '1h',
    algorithm: 'HS256',
  });
  res.json({ token });
});
""",
            "Java (Spring Boot)": """\
// GOOD: bcrypt via Spring Security, expiry, env-based secret
@PostMapping("/api/v1/login")
public ResponseEntity<?> login(@RequestBody LoginRequest req) {
    User user = userRepo.findByEmail(req.getEmail())
        .orElseThrow(() -> new UnauthorizedException("Invalid credentials"));
    if (!passwordEncoder.matches(req.getPassword(), user.getPasswordHash())) {
        throw new UnauthorizedException("Invalid credentials");
    }
    String token = Jwts.builder()
        .setSubject(user.getId().toString())
        .setIssuedAt(new Date())
        .setExpiration(Date.from(Instant.now().plusSeconds(3600)))
        .signWith(Keys.hmacShaKeyFor(secret.getBytes()), SignatureAlgorithm.HS256)
        .compact();
    return ResponseEntity.ok(new TokenResponse(token));
}
""",
            "Go": """\
// GOOD: bcrypt, expiry, env secret
func Login(c *gin.Context) {
    var creds Credentials
    json.NewDecoder(c.Request.Body).Decode(&creds)
    user := findUser(creds.Email)
    if user == nil || bcrypt.CompareHashAndPassword([]byte(user.PwHash),
                                                    []byte(creds.Password)) != nil {
        c.JSON(401, gin.H{"error": "invalid credentials"})
        return
    }
    claims := jwt.MapClaims{
        "sub": user.ID,
        "exp": time.Now().Add(time.Hour).Unix(),
    }
    token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
    ss, _ := token.SignedString([]byte(os.Getenv("JWT_SECRET")))
    c.JSON(200, gin.H{"token": ss})
}
""",
            "PHP (Laravel)": """\
// GOOD: Hash check, throttle, Sanctum token with expiry
public function login(Request $request)
{
    $request->validate(['email' => 'required|email', 'password' => 'required']);
    if (RateLimiter::tooManyAttempts('login:'.$request->ip(), 5)) {
        return response()->json(['error' => 'Too many attempts'], 429);
    }
    $user = User::where('email', $request->email)->first();
    if (!$user || !Hash::check($request->password, $user->password)) {
        RateLimiter::hit('login:'.$request->ip());
        return response()->json(['error' => 'Unauthorized'], 401);
    }
    RateLimiter::clear('login:'.$request->ip());
    $token = $user->createToken('api', ['*'], now()->addHour())->plainTextToken;
    return response()->json(['token' => $token]);
}
""",
        },
        "curl_attacks": [
            {
                "title": "Credential stuffing / brute-force",
                "command": (
                    "# Using a leaked password list (rockyou.txt)\n"
                    "while IFS= read -r pwd; do\n"
                    "  STATUS=$(curl -s -o /dev/null -w '%{http_code}' \\\n"
                    "    -X POST https://api.example.com/api/v1/login \\\n"
                    "    -H 'Content-Type: application/json' \\\n"
                    "    -d \"{\\\"email\\\":\\\"victim@example.com\\\",\\\"password\\\":\\\"$pwd\\\"}\")\n"
                    "  [ \"$STATUS\" = '200' ] && echo \"FOUND: $pwd\" && break\n"
                    "done < rockyou.txt"
                ),
                "explanation": "Without rate limiting or account lockout, thousands of passwords can be tried in seconds.",
            },
            {
                "title": "JWT 'none' algorithm attack",
                "command": (
                    "# 1. Decode the original JWT (base64)\n"
                    "# Header: {\"alg\":\"none\",\"typ\":\"JWT\"}\n"
                    "# Payload: {\"sub\":1,\"role\":\"admin\"}\n"
                    "HEADER=$(echo -n '{\"alg\":\"none\",\"typ\":\"JWT\"}' | base64 -w0 | tr -d '=')\n"
                    "PAYLOAD=$(echo -n '{\"sub\":1,\"role\":\"admin\"}' | base64 -w0 | tr -d '=')\n"
                    "FORGED=\"$HEADER.$PAYLOAD.\"\n\n"
                    "curl -H \"Authorization: Bearer $FORGED\" \\\n"
                    "     https://api.example.com/api/v1/admin/users"
                ),
                "explanation": "If the server accepts tokens signed with algorithm 'none', signatures are completely bypassed.",
            },
        ],
        "propagation": (
            "**Credential Stuffing:** Breached credential lists from dark-web forums are "
            "fed into automated tools (Sentry MBA, OpenBullet). One valid hit gives "
            "complete account access.\n\n"
            "**Token Theft:** Weak secrets can be cracked offline with hashcat. "
            "Stolen tokens from XSS or network sniffing give persistent access without "
            "requiring the password.\n\n"
            "**Privilege Escalation:** Forged JWTs (none-algorithm, RS→HS confusion) "
            "can elevate a regular user to admin without knowing the signing key.\n\n"
            "**Lateral Movement:** Once authenticated as an admin, the attacker can "
            "reset other users' passwords, extract the full user database, or inject "
            "malicious data.\n\n"
            "**Business Impact:** Full account takeovers, data breaches, financial fraud, "
            "regulatory penalties."
        ),
        "references": [
            {"title": "OWASP API2:2023 Broken Authentication", "url": "https://owasp.org/API-Security/editions/2023/en/0xa2-broken-authentication/"},
            {"title": "OWASP ASVS V2 – Authentication", "url": "https://owasp.org/www-project-application-security-verification-standard/"},
            {"title": "OWASP Cheat Sheet – Authentication", "url": "https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html"},
            {"title": "OWASP Cheat Sheet – JWT Security", "url": "https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html"},
            {"title": "PortSwigger – JWT Attacks", "url": "https://portswigger.net/web-security/jwt"},
        ],
    },

    # ─────────────────────────────────────────────────────────────────────────
    # API3:2023 – Broken Object Property Level Authorization
    # ─────────────────────────────────────────────────────────────────────────
    {
        "id": "API3",
        "title": "API3:2023 – Broken Object Property Level Authorization",
        "short_desc": (
            "APIs expose more object properties than the consumer needs (Excessive Data "
            "Exposure) or allow consumers to update sensitive properties they should not "
            "control (Mass Assignment). Both stem from missing field-level authorization."
        ),
        "risk_rating": "High",
        "vulnerable_code": {
            "Python (Flask)": """\
# BAD – Mass Assignment: user can set their own role
@app.route("/api/v1/users/<int:uid>", methods=["PUT"])
@jwt_required()
def update_user(uid):
    user = db.session.get(User, uid)
    for key, value in request.json.items():  # ← accepts ALL fields including 'role'
        setattr(user, key, value)
    db.session.commit()
    return jsonify(user.to_dict())           # ← also leaks password_hash!
""",
            "JavaScript (Express)": """\
// BAD – Excessive Data Exposure + Mass Assignment
app.put('/api/v1/users/:id', authenticate, async (req, res) => {
  const user = await User.findById(req.params.id);
  Object.assign(user, req.body);  // ← mass assignment (role, isAdmin, etc.)
  await user.save();
  res.json(user);                  // ← returns full object including passwordHash
});
""",
            "Java (Spring Boot)": """\
// BAD – Mass Assignment via @RequestBody directly into the entity
@PutMapping("/api/v1/users/{id}")
public ResponseEntity<User> updateUser(@PathVariable Long id,
                                        @RequestBody User updatedUser) {
    // updatedUser may contain role='ADMIN', isVerified=true, etc.
    updatedUser.setId(id);
    return ResponseEntity.ok(userRepository.save(updatedUser)); // saves ALL fields
}
""",
            "Go": """\
// BAD – Bind JSON directly to the model struct (includes Role field)
func UpdateUser(c *gin.Context) {
    id := c.Param("id")
    var user User
    db.First(&user, id)
    c.ShouldBindJSON(&user)  // ← attacker can set user.Role
    db.Save(&user)
    c.JSON(200, user)         // ← leaks PasswordHash
}
""",
            "PHP (Laravel)": """\
// BAD – $fillable not defined; mass assignment + data over-exposure
public function update(Request $request, $id)
{
    $user = User::findOrFail($id);
    $user->update($request->all()); // ← all fields including 'role'
    return response()->json($user); // ← returns password_hash, role, etc.
}
""",
        },
        "secure_code": {
            "Python (Flask)": """\
# GOOD – Allowlist updatable fields; return only safe fields
UPDATABLE_FIELDS = {"name", "bio", "avatar_url"}

@app.route("/api/v1/users/<int:uid>", methods=["PUT"])
@jwt_required()
def update_user(uid):
    if get_jwt_identity() != uid:
        return jsonify({"error": "Forbidden"}), 403
    user = db.session.get(User, uid)
    payload = {k: v for k, v in request.json.items() if k in UPDATABLE_FIELDS}
    for key, value in payload.items():
        setattr(user, key, value)
    db.session.commit()
    return jsonify({"id": user.id, "name": user.name, "bio": user.bio})
""",
            "JavaScript (Express)": """\
// GOOD – Explicit field whitelist + safe DTO response
const ALLOWED = ['name', 'bio', 'avatarUrl'];

app.put('/api/v1/users/:id', authenticate, async (req, res) => {
  if (req.user.id !== req.params.id) return res.sendStatus(403);
  const updates = Object.fromEntries(
    Object.entries(req.body).filter(([k]) => ALLOWED.includes(k))
  );
  const user = await User.findByIdAndUpdate(req.params.id, updates, { new: true })
                          .select('name bio avatarUrl email');  // safe projection
  res.json(user);
});
""",
            "Java (Spring Boot)": """\
// GOOD – Use a DTO, map only allowed fields
public record UpdateUserRequest(String name, String bio, String avatarUrl) {}

@PutMapping("/api/v1/users/{id}")
public ResponseEntity<UserResponse> updateUser(@PathVariable Long id,
                                                @RequestBody UpdateUserRequest dto,
                                                Principal principal) {
    User user = userRepo.findById(id).orElseThrow();
    if (!user.getUsername().equals(principal.getName())) throw new ForbiddenException();
    user.setName(dto.name());
    user.setBio(dto.bio());
    return ResponseEntity.ok(new UserResponse(user)); // DTO — no password/role
}
""",
            "Go": """\
// GOOD – Separate update struct without sensitive fields
type UpdateUserInput struct {
    Name      string `json:"name"`
    Bio       string `json:"bio"`
    AvatarURL string `json:"avatar_url"`
}

func UpdateUser(c *gin.Context) {
    userID := c.MustGet("userID").(uint)
    id, _ := strconv.ParseUint(c.Param("id"), 10, 64)
    if userID != uint(id) {
        c.JSON(403, gin.H{"error": "forbidden"})
        return
    }
    var input UpdateUserInput
    c.ShouldBindJSON(&input)
    db.Model(&User{}).Where("id = ?", id).Updates(input)
    c.JSON(200, gin.H{"name": input.Name, "bio": input.Bio})
}
""",
            "PHP (Laravel)": """\
// GOOD – validate + fill only safe fields, return resource
public function update(Request $request, $id)
{
    $request->validate(['name' => 'string|max:255', 'bio' => 'string|max:1000']);
    $user = User::findOrFail($id);
    $this->authorize('update', $user);  // policy check
    $user->fill($request->only(['name', 'bio', 'avatar_url']))->save();
    return new UserResource($user); // resource hides password/role
}
""",
        },
        "curl_attacks": [
            {
                "title": "Mass Assignment — self-promote to admin",
                "command": (
                    "curl -X PUT https://api.example.com/api/v1/users/42 \\\n"
                    "  -H 'Authorization: Bearer $TOKEN' \\\n"
                    "  -H 'Content-Type: application/json' \\\n"
                    "  -d '{\"name\":\"Alice\",\"role\":\"admin\",\"isVerified\":true}'"
                ),
                "explanation": "If the API accepts all JSON fields without a whitelist, the attacker can write to any column including 'role'.",
            },
            {
                "title": "Excessive Data Exposure — harvest sensitive fields",
                "command": (
                    "curl https://api.example.com/api/v1/users/42 \\\n"
                    "  -H 'Authorization: Bearer $TOKEN'"
                ),
                "explanation": "The response might include password_hash, internal flags, or PII not intended for the client.",
            },
        ],
        "propagation": (
            "**Mass Assignment:** An attacker sends extra JSON keys that map to "
            "privileged model fields ('role', 'isAdmin', 'creditBalance'). "
            "A single API call can promote an account to administrator.\n\n"
            "**Excessive Data Exposure:** Aggregated over many user IDs (via BOLA), "
            "password hashes, SSNs, or internal tokens can be bulk-harvested and cracked "
            "offline or sold.\n\n"
            "**Downstream Impact:** Admin accounts can be used to read all data, disable "
            "security controls, create backdoor accounts, or delete audit logs.\n\n"
            "**Business Impact:** Unauthorized access, regulatory violations, brand damage."
        ),
        "references": [
            {"title": "OWASP API3:2023 Broken Object Property Level Authorization", "url": "https://owasp.org/API-Security/editions/2023/en/0xa3-broken-object-property-level-authorization/"},
            {"title": "OWASP Cheat Sheet – Mass Assignment", "url": "https://cheatsheetseries.owasp.org/cheatsheets/Mass_Assignment_Cheat_Sheet.html"},
            {"title": "OWASP ASVS V4 – Access Control", "url": "https://owasp.org/www-project-application-security-verification-standard/"},
        ],
    },

    # ─────────────────────────────────────────────────────────────────────────
    # API4:2023 – Unrestricted Resource Consumption
    # ─────────────────────────────────────────────────────────────────────────
    {
        "id": "API4",
        "title": "API4:2023 – Unrestricted Resource Consumption",
        "short_desc": (
            "APIs that do not restrict the size or frequency of requests can be abused "
            "to cause Denial-of-Service, inflate cloud costs, or mine data at scale. "
            "This covers missing rate limits, unbounded query results, and unbounded "
            "upload sizes."
        ),
        "risk_rating": "High",
        "vulnerable_code": {
            "Python (Flask)": """\
# BAD: No rate limit, no pagination, no result cap
@app.route("/api/v1/search")
def search():
    q = request.args.get("q", "")
    results = Product.query.filter(Product.name.contains(q)).all()  # ← returns ALL
    return jsonify([p.to_dict() for p in results])
""",
            "JavaScript (Express)": """\
// BAD: Accepts arbitrarily large request bodies, no throttle
app.use(express.json());   // default limit is 100kb but can be overridden or absent
app.post('/api/v1/upload', async (req, res) => {
  await processFile(req.body.data);  // no size check
  res.json({ ok: true });
});
""",
            "Java (Spring Boot)": """\
// BAD: No paging, returns entire table
@GetMapping("/api/v1/products")
public List<Product> getAllProducts() {
    return productRepository.findAll();  // could be millions of rows
}
""",
            "Go": """\
// BAD: No rate limit middleware, no result limit
func SearchProducts(c *gin.Context) {
    q := c.Query("q")
    var products []Product
    db.Where("name LIKE ?", "%"+q+"%").Find(&products) // unbounded
    c.JSON(200, products)
}
""",
            "PHP (Laravel)": """\
// BAD: No throttle, no pagination
public function index(Request $request)
{
    return response()->json(Product::all()); // no limit
}
""",
        },
        "secure_code": {
            "Python (Flask)": """\
# GOOD: Rate limiting, max page size, explicit pagination
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

limiter = Limiter(get_remote_address, app=app, default_limits=["200 per day","50 per hour"])

@app.route("/api/v1/search")
@limiter.limit("30 per minute")
def search():
    q = request.args.get("q", "")
    page = max(1, int(request.args.get("page", 1)))
    per_page = min(int(request.args.get("per_page", 20)), 100)  # cap at 100
    paginated = (Product.query
                 .filter(Product.name.contains(q))
                 .paginate(page=page, per_page=per_page, error_out=False))
    return jsonify({
        "items": [p.to_dict() for p in paginated.items],
        "total": paginated.total,
        "page": page,
        "pages": paginated.pages,
    })
""",
            "JavaScript (Express)": """\
// GOOD: Limit body size, rate limit, paginate
const rateLimit = require('express-rate-limit');
app.use(express.json({ limit: '1mb' }));

const searchLimiter = rateLimit({ windowMs: 60_000, max: 30 });

app.get('/api/v1/search', searchLimiter, async (req, res) => {
  const page = Math.max(1, parseInt(req.query.page) || 1);
  const limit = Math.min(parseInt(req.query.limit) || 20, 100);
  const skip = (page - 1) * limit;
  const [items, total] = await Promise.all([
    Product.find({ name: new RegExp(req.query.q, 'i') }).skip(skip).limit(limit),
    Product.countDocuments({ name: new RegExp(req.query.q, 'i') }),
  ]);
  res.json({ items, total, page, pages: Math.ceil(total / limit) });
});
""",
            "Java (Spring Boot)": """\
// GOOD: Pageable + rate limit (Bucket4j)
@GetMapping("/api/v1/products")
public ResponseEntity<Page<ProductDTO>> getProducts(
        @RequestParam(defaultValue = "0") int page,
        @RequestParam(defaultValue = "20") int size) {
    int cappedSize = Math.min(size, 100);
    Pageable pageable = PageRequest.of(page, cappedSize);
    return ResponseEntity.ok(productRepository.findAll(pageable).map(ProductDTO::from));
}
""",
            "Go": """\
// GOOD: Rate limiter middleware + bounded query
func SearchProducts(c *gin.Context) {
    q := c.Query("q")
    page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
    limit, _ := strconv.Atoi(c.DefaultQuery("limit", "20"))
    if limit > 100 { limit = 100 }
    offset := (page - 1) * limit
    var products []Product
    db.Where("name LIKE ?", "%"+q+"%").Offset(offset).Limit(limit).Find(&products)
    c.JSON(200, gin.H{"items": products, "page": page})
}
""",
            "PHP (Laravel)": """\
// GOOD: throttle middleware + paginate
Route::middleware('throttle:60,1')->group(function () {
    Route::get('/api/v1/products', [ProductController::class, 'index']);
});

public function index(Request $request)
{
    $perPage = min($request->input('per_page', 20), 100);
    return ProductResource::collection(Product::paginate($perPage));
}
""",
        },
        "curl_attacks": [
            {
                "title": "DoS — flood the search endpoint",
                "command": (
                    "# Send 10 000 concurrent requests\n"
                    "seq 1 10000 | xargs -P 100 -I{} \\\n"
                    "  curl -s https://api.example.com/api/v1/search?q=a \\\n"
                    "  -o /dev/null"
                ),
                "explanation": "Without rate limiting, the database executes unbounded full-table scans for every request, exhausting CPU and memory.",
            },
            {
                "title": "Data scraping — dump entire catalog",
                "command": (
                    "for PAGE in $(seq 0 999); do\n"
                    "  curl -s \"https://api.example.com/api/v1/products?page=$PAGE&size=1000\" >> catalog.json\n"
                    "done"
                ),
                "explanation": "Without a page-size cap, the attacker retrieves a million-row catalog in 1 000 requests.",
            },
        ],
        "propagation": (
            "**DoS / Service Disruption:** Flooding endpoints with requests saturates "
            "CPU, memory, or database connection pools, making the service unavailable "
            "to legitimate users.\n\n"
            "**Cloud Cost Explosion:** Pay-per-request APIs (AWS Lambda, Cloud Functions) "
            "can incur thousands of dollars in minutes.\n\n"
            "**Data Harvesting:** Unbounded pagination lets competitors or scrapers "
            "download proprietary data in bulk.\n\n"
            "**Resource Exhaustion Chain:** Large file uploads without limits can fill "
            "disk partitions, causing dependent services (databases, log collectors) "
            "to crash.\n\n"
            "**Business Impact:** SLA violations, financial losses, complete outage."
        ),
        "references": [
            {"title": "OWASP API4:2023 Unrestricted Resource Consumption", "url": "https://owasp.org/API-Security/editions/2023/en/0xa4-unrestricted-resource-consumption/"},
            {"title": "OWASP Cheat Sheet – Denial of Service", "url": "https://cheatsheetseries.owasp.org/cheatsheets/Denial_of_Service_Cheat_Sheet.html"},
            {"title": "OWASP Cheat Sheet – REST Security", "url": "https://cheatsheetseries.owasp.org/cheatsheets/REST_Security_Cheat_Sheet.html"},
        ],
    },

    # ─────────────────────────────────────────────────────────────────────────
    # API5:2023 – Broken Function Level Authorization
    # ─────────────────────────────────────────────────────────────────────────
    {
        "id": "API5",
        "title": "API5:2023 – Broken Function Level Authorization (BFLA)",
        "short_desc": (
            "Complex access control policies (roles, groups, admin vs. user paths) "
            "are not enforced at the function level. Attackers discover hidden "
            "administrative endpoints by guessing URL patterns and invoke them without "
            "proper authorization."
        ),
        "risk_rating": "High",
        "vulnerable_code": {
            "Python (Flask)": """\
# BAD: Admin endpoint is 'hidden' by URL convention but has no auth check
@app.route("/api/v1/internal/users", methods=["DELETE"])
@jwt_required()                       # ← only checks that a valid token exists
def delete_all_users():               #    does NOT check role == 'admin'
    User.query.delete()
    db.session.commit()
    return jsonify({"deleted": True})
""",
            "JavaScript (Express)": """\
// BAD: Admin middleware only checks authentication, not role
app.delete('/api/v1/admin/users', authenticate, async (req, res) => {
  // 'authenticate' verifies token; there is no role check here
  await User.deleteMany({});
  res.json({ deleted: true });
});
""",
            "Java (Spring Boot)": """\
// BAD: @PreAuthorize missing on admin endpoint
@DeleteMapping("/api/v1/admin/users")
// Missing: @PreAuthorize("hasRole('ADMIN')")
public ResponseEntity<Void> deleteAllUsers() {
    userRepository.deleteAll();
    return ResponseEntity.noContent().build();
}
""",
            "Go": """\
// BAD: No role check on destructive admin route
r.DELETE("/api/v1/admin/users", AuthMiddleware(), func(c *gin.Context) {
    // AuthMiddleware only validates the JWT, does not check role
    db.Where("1 = 1").Delete(&User{})
    c.JSON(200, gin.H{"deleted": true})
})
""",
            "PHP (Laravel)": """\
// BAD: Only authenticated, not authorized as admin
Route::delete('/api/v1/admin/users', [AdminController::class, 'deleteAll'])
     ->middleware('auth:sanctum');  // ← missing 'role:admin' check
""",
        },
        "secure_code": {
            "Python (Flask)": """\
# GOOD: Explicit role check + decorator
def admin_required(fn):
    @wraps(fn)
    @jwt_required()
    def wrapper(*args, **kwargs):
        claims = get_jwt()
        if claims.get("role") != "admin":
            return jsonify({"error": "Admin access required"}), 403
        return fn(*args, **kwargs)
    return wrapper

@app.route("/api/v1/admin/users", methods=["DELETE"])
@admin_required
def delete_all_users():
    User.query.delete()
    db.session.commit()
    return jsonify({"deleted": True})
""",
            "JavaScript (Express)": """\
// GOOD: Separate role-checking middleware
function requireAdmin(req, res, next) {
  if (!req.user || req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Admin access required' });
  }
  next();
}

app.delete('/api/v1/admin/users', authenticate, requireAdmin, async (req, res) => {
  await User.deleteMany({});
  res.json({ deleted: true });
});
""",
            "Java (Spring Boot)": """\
// GOOD: @PreAuthorize with role requirement
@DeleteMapping("/api/v1/admin/users")
@PreAuthorize("hasRole('ADMIN')")
public ResponseEntity<Void> deleteAllUsers() {
    userRepository.deleteAll();
    return ResponseEntity.noContent().build();
}
""",
            "Go": """\
// GOOD: Dedicated admin middleware that checks role claim
func AdminMiddleware() gin.HandlerFunc {
    return func(c *gin.Context) {
        role := c.MustGet("role").(string)
        if role != "admin" {
            c.AbortWithStatusJSON(403, gin.H{"error": "admin access required"})
            return
        }
        c.Next()
    }
}

r.DELETE("/api/v1/admin/users", AuthMiddleware(), AdminMiddleware(), func(c *gin.Context) {
    db.Where("1 = 1").Delete(&User{})
    c.JSON(200, gin.H{"deleted": true})
})
""",
            "PHP (Laravel)": """\
// GOOD: role middleware
Route::delete('/api/v1/admin/users', [AdminController::class, 'deleteAll'])
     ->middleware(['auth:sanctum', 'role:admin']);
""",
        },
        "curl_attacks": [
            {
                "title": "Discover hidden admin endpoints via path guessing",
                "command": (
                    "# Fuzz admin paths with ffuf\n"
                    "ffuf -w /usr/share/wordlists/api_paths.txt \\\n"
                    "     -u https://api.example.com/api/v1/FUZZ \\\n"
                    "     -H 'Authorization: Bearer $USER_TOKEN' \\\n"
                    "     -mc 200,204\n\n"
                    "# Then call the discovered admin endpoint\n"
                    "curl -X DELETE https://api.example.com/api/v1/admin/users \\\n"
                    "     -H 'Authorization: Bearer $USER_TOKEN'"
                ),
                "explanation": "A regular user's token works on admin endpoints because the server only checks authentication, not role.",
            },
            {
                "title": "HTTP method override to bypass WAF",
                "command": (
                    "curl -X POST https://api.example.com/api/v1/admin/users \\\n"
                    "  -H 'X-HTTP-Method-Override: DELETE' \\\n"
                    "  -H 'Authorization: Bearer $USER_TOKEN'"
                ),
                "explanation": "Some frameworks honour X-HTTP-Method-Override, allowing method restrictions to be bypassed.",
            },
        ],
        "propagation": (
            "**Endpoint Discovery:** API documentation (Swagger/OpenAPI), JavaScript "
            "bundles, and Google dorking reveal admin endpoint patterns. Fuzzing tools "
            "enumerate the rest in minutes.\n\n"
            "**Destructive Actions:** Delete-all, reset-database, disable-MFA endpoints "
            "can cause catastrophic data loss with a single request.\n\n"
            "**Account Takeover at Scale:** Admin endpoints that reset passwords or "
            "issue tokens give the attacker full control of every account.\n\n"
            "**Audit Log Tampering:** Admin routes that clear logs remove evidence of "
            "the breach, extending attacker dwell time.\n\n"
            "**Business Impact:** Complete system compromise, data destruction, "
            "regulatory breach, loss of customer trust."
        ),
        "references": [
            {"title": "OWASP API5:2023 Broken Function Level Authorization", "url": "https://owasp.org/API-Security/editions/2023/en/0xa5-broken-function-level-authorization/"},
            {"title": "OWASP ASVS V4 – Access Control", "url": "https://owasp.org/www-project-application-security-verification-standard/"},
            {"title": "OWASP Cheat Sheet – Access Control", "url": "https://cheatsheetseries.owasp.org/cheatsheets/Access_Control_Cheat_Sheet.html"},
            {"title": "OWASP Proactive Controls – Enforce Access Controls", "url": "https://owasp.org/www-project-proactive-controls/"},
        ],
    },

    # ─────────────────────────────────────────────────────────────────────────
    # API6:2023 – Unrestricted Access to Sensitive Business Flows
    # ─────────────────────────────────────────────────────────────────────────
    {
        "id": "API6",
        "title": "API6:2023 – Unrestricted Access to Sensitive Business Flows",
        "short_desc": (
            "APIs that expose sensitive business flows (buy, checkout, vote, referral) "
            "without anti-automation controls can be abused by bots to gain unfair "
            "advantage: bulk purchasing, scalping, reward fraud, or credential stuffing "
            "attacks on business logic."
        ),
        "risk_rating": "High",
        "vulnerable_code": {
            "Python (Flask)": """\
# BAD: No bot detection, no per-user purchase limit
@app.route("/api/v1/buy", methods=["POST"])
@jwt_required()
def buy_item():
    item_id = request.json["item_id"]
    qty = request.json.get("quantity", 1)
    item = Item.query.get(item_id)
    if item.stock >= qty:
        item.stock -= qty
        Order.create(user_id=get_jwt_identity(), item_id=item_id, qty=qty)
        db.session.commit()
        return jsonify({"status": "purchased"})
    return jsonify({"error": "Out of stock"}), 409
""",
            "JavaScript (Express)": """\
// BAD: No CAPTCHA, no purchase frequency check
app.post('/api/v1/referral/claim', authenticate, async (req, res) => {
  const bonus = await createReferralBonus(req.user.id, req.body.code);
  res.json({ bonus });
  // Attacker creates 1000 accounts programmatically and claims bonus each time
});
""",
            "Java (Spring Boot)": """\
// BAD: Flash sale endpoint with no per-user limit
@PostMapping("/api/v1/flash-sale/buy")
public ResponseEntity<?> buyFlashItem(@RequestBody BuyRequest req,
                                       Principal principal) {
    // No check: has this user already bought in this flash sale?
    return ResponseEntity.ok(orderService.create(principal.getName(), req));
}
""",
            "Go": """\
// BAD: Vote endpoint — no cooldown, allows unlimited votes
func VoteItem(c *gin.Context) {
    userID := c.MustGet("userID").(uint)
    itemID := c.Param("id")
    db.Create(&Vote{UserID: userID, ItemID: itemID})
    c.JSON(200, gin.H{"ok": true})
}
""",
            "PHP (Laravel)": """\
// BAD: Coupon can be applied unlimited times
public function applyCoupon(Request $request)
{
    $coupon = Coupon::where('code', $request->code)->first();
    // No check: has this user already used this coupon?
    Cart::applyDiscount($request->user(), $coupon->discount);
    return response()->json(['discount_applied' => true]);
}
""",
        },
        "secure_code": {
            "Python (Flask)": """\
# GOOD: Per-user limit + rate limit + device fingerprint check
@app.route("/api/v1/buy", methods=["POST"])
@jwt_required()
@limiter.limit("5 per hour")          # rate limit per IP
def buy_item():
    user_id = get_jwt_identity()
    item_id = request.json["item_id"]
    qty = int(request.json.get("quantity", 1))
    if qty > 2:                        # business rule: max 2 per order
        return jsonify({"error": "Max 2 per customer"}), 400
    # Check total purchased this week
    week_purchases = Order.query.filter(
        Order.user_id == user_id,
        Order.item_id == item_id,
        Order.created_at >= datetime.utcnow() - timedelta(weeks=1)
    ).count()
    if week_purchases + qty > 2:
        return jsonify({"error": "Purchase limit reached"}), 429
    item = Item.query.with_for_update().get(item_id)
    if item.stock < qty:
        return jsonify({"error": "Out of stock"}), 409
    item.stock -= qty
    Order.create(user_id=user_id, item_id=item_id, qty=qty)
    db.session.commit()
    return jsonify({"status": "purchased"})
""",
            "JavaScript (Express)": """\
// GOOD: One referral per account + CAPTCHA verification
app.post('/api/v1/referral/claim', authenticate, async (req, res) => {
  // Verify CAPTCHA token
  const captchaOk = await verifyCaptcha(req.body.captchaToken);
  if (!captchaOk) return res.status(400).json({ error: 'CAPTCHA failed' });

  const existing = await ReferralClaim.findOne({ userId: req.user.id });
  if (existing) return res.status(409).json({ error: 'Already claimed' });

  const bonus = await createReferralBonus(req.user.id, req.body.code);
  res.json({ bonus });
});
""",
            "Java (Spring Boot)": """\
// GOOD: Idempotent purchase with distributed lock + per-user limit
@PostMapping("/api/v1/flash-sale/buy")
public ResponseEntity<?> buyFlashItem(@RequestBody BuyRequest req,
                                       Principal principal) {
    String lockKey = "flash:" + req.getItemId() + ":user:" + principal.getName();
    boolean acquired = redisLock.acquire(lockKey, 5, TimeUnit.SECONDS);
    if (!acquired) return ResponseEntity.status(429).build();
    try {
        long userOrders = orderRepo.countByUserAndItemAndSaleId(
            principal.getName(), req.getItemId(), req.getSaleId());
        if (userOrders >= 1)
            return ResponseEntity.status(409).body("Already purchased");
        return ResponseEntity.ok(orderService.create(principal.getName(), req));
    } finally {
        redisLock.release(lockKey);
    }
}
""",
            "Go": """\
// GOOD: Vote cooldown stored in Redis
func VoteItem(c *gin.Context) {
    userID := c.MustGet("userID").(uint)
    itemID := c.Param("id")
    key := fmt.Sprintf("vote:%d:%s", userID, itemID)
    ok, _ := rdb.SetNX(ctx, key, 1, 24*time.Hour).Result() // 1 vote per day
    if !ok {
        c.JSON(429, gin.H{"error": "you already voted today"})
        return
    }
    db.Create(&Vote{UserID: userID, ItemID: itemID})
    c.JSON(200, gin.H{"ok": true})
}
""",
            "PHP (Laravel)": """\
// GOOD: One-time coupon tracked per user
public function applyCoupon(Request $request)
{
    $coupon = Coupon::where('code', $request->code)->firstOrFail();
    $used = CouponUsage::where('user_id', $request->user()->id)
                        ->where('coupon_id', $coupon->id)->exists();
    if ($used) {
        return response()->json(['error' => 'Coupon already used'], 409);
    }
    CouponUsage::create(['user_id' => $request->user()->id, 'coupon_id' => $coupon->id]);
    Cart::applyDiscount($request->user(), $coupon->discount);
    return response()->json(['discount_applied' => true]);
}
""",
        },
        "curl_attacks": [
            {
                "title": "Scalping bot — buy all limited-edition stock",
                "command": (
                    "# Bot loop — buy as many units as possible before others can\n"
                    "for i in $(seq 1 500); do\n"
                    "  curl -s -X POST https://api.example.com/api/v1/buy \\\n"
                    "    -H 'Authorization: Bearer $TOKEN' \\\n"
                    "    -H 'Content-Type: application/json' \\\n"
                    "    -d '{\"item_id\":99,\"quantity\":10}' &\n"
                    "done\nwait"
                ),
                "explanation": "Parallel requests without a per-user limit drain stock in seconds, preventing legitimate buyers from purchasing.",
            },
            {
                "title": "Referral fraud — mass claim with fake accounts",
                "command": (
                    "# Create 100 fake accounts and claim referral bonus each time\n"
                    "for i in $(seq 1 100); do\n"
                    "  TOKEN=$(curl -s -X POST https://api.example.com/auth/register \\\n"
                    "    -d \"{\\\"email\\\":\\\"bot$i@tempmail.com\\\",\\\"password\\\":\\\"pass\\\"}\" | jq -r .token)\n"
                    "  curl -s -X POST https://api.example.com/api/v1/referral/claim \\\n"
                    "    -H \"Authorization: Bearer $TOKEN\" \\\n"
                    "    -d '{\"code\":\"REF123\"}'\n"
                    "done"
                ),
                "explanation": "Without email verification or device fingerprinting, each new account gets the referral bonus.",
            },
        ],
        "propagation": (
            "**Automated Abuse:** Bots execute business transactions faster and at higher "
            "volume than humans. Without anti-automation controls, any valuable action "
            "(buy, vote, redeem) can be gamed.\n\n"
            "**Financial Loss:** Scalpers resell scarce inventory for profit; referral "
            "fraud and coupon abuse drain promotional budgets.\n\n"
            "**Platform Integrity:** Fake votes, reviews, or likes undermine trust in "
            "community features.\n\n"
            "**Cascading Load:** Coordinated bot traffic causes the same resource "
            "exhaustion issues as API4, compounding the attack surface.\n\n"
            "**Business Impact:** Revenue loss, competitive disadvantage, user "
            "frustration, brand damage."
        ),
        "references": [
            {"title": "OWASP API6:2023 Unrestricted Access to Sensitive Business Flows", "url": "https://owasp.org/API-Security/editions/2023/en/0xa6-unrestricted-access-to-sensitive-business-flows/"},
            {"title": "OWASP Automated Threats to Web Applications", "url": "https://owasp.org/www-project-automated-threats-to-web-applications/"},
            {"title": "OWASP Cheat Sheet – Credential Stuffing Prevention", "url": "https://cheatsheetseries.owasp.org/cheatsheets/Credential_Stuffing_Prevention_Cheat_Sheet.html"},
        ],
    },

    # ─────────────────────────────────────────────────────────────────────────
    # API7:2023 – Server Side Request Forgery
    # ─────────────────────────────────────────────────────────────────────────
    {
        "id": "API7",
        "title": "API7:2023 – Server Side Request Forgery (SSRF)",
        "short_desc": (
            "SSRF flaws occur whenever an API fetches a remote resource based on a "
            "user-supplied URL without validating or sanitising it. Attackers can "
            "force the server to make requests to internal services, cloud metadata "
            "endpoints, or arbitrary external hosts."
        ),
        "risk_rating": "High",
        "vulnerable_code": {
            "Python (Flask)": """\
# BAD: Fetches any URL provided by the user
import requests

@app.route("/api/v1/fetch-preview", methods=["POST"])
@jwt_required()
def fetch_preview():
    url = request.json["url"]       # ← no validation
    resp = requests.get(url, timeout=5)
    return jsonify({"content": resp.text})
""",
            "JavaScript (Express)": """\
// BAD: Proxy endpoint with no URL validation
const axios = require('axios');

app.post('/api/v1/webhook-test', authenticate, async (req, res) => {
  const response = await axios.get(req.body.url);  // ← any URL
  res.json({ body: response.data });
});
""",
            "Java (Spring Boot)": """\
// BAD: RestTemplate fetches user-supplied URL
@PostMapping("/api/v1/import")
public ResponseEntity<String> importData(@RequestBody Map<String, String> body) {
    String url = body.get("url");                              // ← no validation
    String data = restTemplate.getForObject(url, String.class);
    return ResponseEntity.ok(data);
}
""",
            "Go": """\
// BAD: User-controlled URL passed directly to http.Get
func FetchPreview(c *gin.Context) {
    url := c.PostForm("url")
    resp, err := http.Get(url)   // ← no validation
    if err != nil {
        c.JSON(500, gin.H{"error": err.Error()})
        return
    }
    defer resp.Body.Close()
    body, _ := io.ReadAll(resp.Body)
    c.JSON(200, gin.H{"content": string(body)})
}
""",
            "PHP (Laravel)": """\
// BAD: cURL with user-supplied URL
public function fetchPreview(Request $request)
{
    $url = $request->input('url');     // ← no validation
    $content = file_get_contents($url);
    return response()->json(['content' => $content]);
}
""",
        },
        "secure_code": {
            "Python (Flask)": """\
# GOOD: URL allowlist + block private ranges
import ipaddress, socket
from urllib.parse import urlparse

ALLOWED_SCHEMES = {"https"}
ALLOWED_DOMAINS = {"partner.example.com", "cdn.example.com"}

def is_safe_url(url: str) -> bool:
    try:
        parsed = urlparse(url)
        if parsed.scheme not in ALLOWED_SCHEMES:
            return False
        if parsed.hostname not in ALLOWED_DOMAINS:
            return False
        # Resolve and block private/loopback IPs
        ip = ipaddress.ip_address(socket.gethostbyname(parsed.hostname))
        return not (ip.is_private or ip.is_loopback or ip.is_link_local)
    except Exception:
        return False

@app.route("/api/v1/fetch-preview", methods=["POST"])
@jwt_required()
def fetch_preview():
    url = request.json["url"]
    if not is_safe_url(url):
        return jsonify({"error": "URL not allowed"}), 400
    resp = requests.get(url, timeout=5, allow_redirects=False)
    return jsonify({"content": resp.text})
""",
            "JavaScript (Express)": """\
// GOOD: Domain allowlist + block internal IPs
const dns = require('dns').promises;
const ipRangeCheck = require('ip-range-check');

const ALLOWED_DOMAINS = ['partner.example.com', 'cdn.example.com'];
const PRIVATE_RANGES = ['10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16', '127.0.0.0/8'];

async function isSafeUrl(url) {
  try {
    const parsed = new URL(url);
    if (!ALLOWED_DOMAINS.includes(parsed.hostname)) return false;
    const { address } = await dns.lookup(parsed.hostname);
    return !ipRangeCheck(address, PRIVATE_RANGES);
  } catch { return false; }
}

app.post('/api/v1/webhook-test', authenticate, async (req, res) => {
  if (!(await isSafeUrl(req.body.url))) {
    return res.status(400).json({ error: 'URL not allowed' });
  }
  const response = await axios.get(req.body.url, { maxRedirects: 0 });
  res.json({ body: response.data });
});
""",
            "Java (Spring Boot)": """\
// GOOD: Allowlist hostname, block RFC-1918 addresses
@PostMapping("/api/v1/import")
public ResponseEntity<String> importData(@RequestBody Map<String, String> body)
        throws Exception {
    String url = body.get("url");
    URI uri = new URI(url);
    String host = uri.getHost();
    if (!ALLOWED_HOSTS.contains(host)) throw new BadRequestException("Host not allowed");
    InetAddress address = InetAddress.getByName(host);
    if (address.isLoopbackAddress() || address.isSiteLocalAddress())
        throw new BadRequestException("Private IPs not allowed");
    String data = restTemplate.getForObject(url, String.class);
    return ResponseEntity.ok(data);
}
""",
            "Go": """\
// GOOD: Allowlist + private IP block
var allowedHosts = map[string]bool{"partner.example.com": true}

func isSafeURL(rawURL string) bool {
    u, err := url.Parse(rawURL)
    if err != nil || !allowedHosts[u.Hostname()] { return false }
    addrs, err := net.LookupHost(u.Hostname())
    if err != nil { return false }
    for _, addr := range addrs {
        ip := net.ParseIP(addr)
        if ip.IsLoopback() || ip.IsPrivate() { return false }
    }
    return true
}

func FetchPreview(c *gin.Context) {
    rawURL := c.PostForm("url")
    if !isSafeURL(rawURL) {
        c.JSON(400, gin.H{"error": "URL not allowed"})
        return
    }
    resp, _ := http.Get(rawURL)
    defer resp.Body.Close()
    body, _ := io.ReadAll(resp.Body)
    c.JSON(200, gin.H{"content": string(body)})
}
""",
            "PHP (Laravel)": """\
// GOOD: Validate URL + block private ranges
public function fetchPreview(Request $request)
{
    $request->validate(['url' => 'required|url']);
    $parsed = parse_url($request->url);
    $allowed = ['partner.example.com', 'cdn.example.com'];
    if (!in_array($parsed['host'], $allowed)) {
        return response()->json(['error' => 'Host not allowed'], 400);
    }
    $ip = gethostbyname($parsed['host']);
    if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE) === false) {
        return response()->json(['error' => 'Private IPs not allowed'], 400);
    }
    $content = Http::timeout(5)->get($request->url)->body();
    return response()->json(['content' => $content]);
}
""",
        },
        "curl_attacks": [
            {
                "title": "Read AWS EC2 metadata (cloud credential theft)",
                "command": (
                    "curl -X POST https://api.example.com/api/v1/fetch-preview \\\n"
                    "  -H 'Authorization: Bearer $TOKEN' \\\n"
                    "  -H 'Content-Type: application/json' \\\n"
                    "  -d '{\"url\":\"http://169.254.169.254/latest/meta-data/iam/security-credentials/\"}'"
                ),
                "explanation": "The AWS metadata service returns temporary IAM credentials giving the attacker full cloud access.",
            },
            {
                "title": "Probe internal services",
                "command": (
                    "# Try internal hosts\n"
                    "for HOST in 10.0.0.1 10.0.0.2 localhost 192.168.1.1; do\n"
                    "  curl -s -X POST https://api.example.com/api/v1/fetch-preview \\\n"
                    "    -H 'Authorization: Bearer $TOKEN' \\\n"
                    "    -H 'Content-Type: application/json' \\\n"
                    "    -d \"{\\\"url\\\":\\\"http://$HOST:8080/\\\"}\"\n"
                    "done"
                ),
                "explanation": "The server probes its own network on behalf of the attacker, mapping internal topology.",
            },
        ],
        "propagation": (
            "**Cloud Metadata Theft:** The IMDSv1 endpoint (169.254.169.254) is reachable "
            "from any EC2/GCP/Azure instance. SSRF returns IAM tokens that grant "
            "full cloud API access — S3, RDS, Lambda — within seconds.\n\n"
            "**Internal Network Pivot:** The attacker uses the server as a proxy to "
            "scan and probe internal databases, Kubernetes API servers, Redis instances, "
            "and other services that are not exposed to the internet.\n\n"
            "**Data Exfiltration:** Internal services often trust traffic from application "
            "servers and require no authentication, making SSRF a direct path to "
            "sensitive data.\n\n"
            "**RCE via Internal Services:** Chaining SSRF with Redis RESP protocol, "
            "Memcached, or Jenkins can lead to Remote Code Execution.\n\n"
            "**Business Impact:** Full cloud account compromise, internal data exfiltration, "
            "lateral movement across the entire infrastructure."
        ),
        "references": [
            {"title": "OWASP API7:2023 Server Side Request Forgery", "url": "https://owasp.org/API-Security/editions/2023/en/0xa7-server-side-request-forgery/"},
            {"title": "OWASP Cheat Sheet – SSRF Prevention", "url": "https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html"},
            {"title": "PortSwigger – SSRF", "url": "https://portswigger.net/web-security/ssrf"},
        ],
    },

    # ─────────────────────────────────────────────────────────────────────────
    # API8:2023 – Security Misconfiguration
    # ─────────────────────────────────────────────────────────────────────────
    {
        "id": "API8",
        "title": "API8:2023 – Security Misconfiguration",
        "short_desc": (
            "Missing hardening, open cloud storage, incorrect HTTP headers, verbose "
            "error messages, unnecessary HTTP methods, and permissive CORS policies "
            "all constitute security misconfigurations that expose APIs to attack."
        ),
        "risk_rating": "High",
        "vulnerable_code": {
            "Python (Flask)": """\
# BAD: Debug mode in production, verbose errors, permissive CORS
from flask import Flask
from flask_cors import CORS

app = Flask(__name__)
app.config["DEBUG"] = True          # ← exposes interactive debugger
app.config["PROPAGATE_EXCEPTIONS"] = True

CORS(app, origins="*")              # ← allows any origin

@app.errorhandler(Exception)
def handle_error(e):
    import traceback
    return {"error": str(e), "trace": traceback.format_exc()}, 500  # ← leaks internals
""",
            "JavaScript (Express)": """\
// BAD: Stack traces in responses, no security headers
const express = require('express');
const app = express();

// Missing: helmet()
// Missing: cors({ origin: ['https://app.example.com'] })

app.use((err, req, res, next) => {
  res.status(500).json({ error: err.message, stack: err.stack }); // ← exposes stack
});
""",
            "Java (Spring Boot)": """\
# BAD application.properties — verbose errors, actuator exposed
server.error.include-stacktrace=always
server.error.include-message=always
# All actuator endpoints are public
management.endpoints.web.exposure.include=*
management.endpoint.health.show-details=always
""",
            "Go": """\
// BAD: Verbose error with internal details
func handler(c *gin.Context) {
    result, err := db.Query("SELECT ...")
    if err != nil {
        c.JSON(500, gin.H{
            "error": err.Error(),      // ← leaks SQL error, table names
            "query": "SELECT ...",     // ← leaks query structure
        })
    }
}
""",
            "PHP (Laravel)": """\
# BAD .env — debug on in production
APP_DEBUG=true
APP_ENV=production   # contradiction — debug exposes full stack traces in JSON
""",
        },
        "secure_code": {
            "Python (Flask)": """\
# GOOD: Debug off, restrictive CORS, generic error responses, security headers
import os
from flask import Flask, jsonify
from flask_cors import CORS
from flask_talisman import Talisman

app = Flask(__name__)
app.config["DEBUG"] = False
app.config["TESTING"] = False

CORS(app, origins=["https://app.example.com"])  # explicit allowlist

Talisman(app,
    content_security_policy={"default-src": "'self'"},
    strict_transport_security=True,
    force_https=True,
)

@app.errorhandler(Exception)
def handle_error(e):
    app.logger.error("Unhandled exception", exc_info=e)   # log internally
    return jsonify({"error": "Internal server error"}), 500  # generic to client
""",
            "JavaScript (Express)": """\
// GOOD: helmet, restrictive CORS, no stack traces
const express = require('express');
const helmet = require('helmet');
const cors = require('cors');

const app = express();
app.use(helmet());
app.use(cors({ origin: 'https://app.example.com', methods: ['GET', 'POST'] }));

app.use((err, req, res, next) => {
  console.error(err);               // log internally
  res.status(500).json({ error: 'Internal server error' }); // generic to client
});
""",
            "Java (Spring Boot)": """\
# GOOD application.properties
server.error.include-stacktrace=never
server.error.include-message=never
# Expose only health endpoint
management.endpoints.web.exposure.include=health
management.endpoint.health.show-details=never
""",
            "Go": """\
// GOOD: Log internally, return generic error
func handler(c *gin.Context) {
    result, err := db.Query("SELECT ...")
    if err != nil {
        log.Printf("DB query error: %v", err)              // internal log
        c.JSON(500, gin.H{"error": "internal server error"}) // generic
        return
    }
    c.JSON(200, result)
}
""",
            "PHP (Laravel)": """\
# GOOD .env
APP_DEBUG=false
APP_ENV=production
LOG_CHANNEL=stack
LOG_LEVEL=error
""",
        },
        "curl_attacks": [
            {
                "title": "Probe verbose error messages for system info",
                "command": (
                    "# Send malformed input to trigger a stack trace\n"
                    "curl -X POST https://api.example.com/api/v1/users \\\n"
                    "  -H 'Content-Type: application/json' \\\n"
                    "  -d '{\"id\":\"not-an-integer\"}'\n\n"
                    "# Response might contain:\n"
                    "# {\"error\": \"invalid input syntax for type integer\",\n"
                    "#  \"trace\": \"at /app/routes/users.py:42 ...\"}"
                ),
                "explanation": "Stack traces leak file paths, library versions, database type, and query structure — all useful for targeted attacks.",
            },
            {
                "title": "Exploit open actuator endpoint",
                "command": (
                    "# Spring Boot actuator — dump environment (secrets in env vars)\n"
                    "curl https://api.example.com/actuator/env\n\n"
                    "# Heap dump — extract all in-memory data\n"
                    "curl https://api.example.com/actuator/heapdump -o heap.hprof"
                ),
                "explanation": "Publicly exposed actuator endpoints can leak secrets, credentials, and all in-memory application data.",
            },
        ],
        "propagation": (
            "**Information Disclosure:** Stack traces, error messages, and actuator "
            "endpoints expose internal architecture, enabling targeted attacks.\n\n"
            "**CORS Misconfig Exploitation:** A wildcard CORS policy allows malicious "
            "websites to make credentialed API calls on behalf of logged-in users "
            "(cross-site data theft).\n\n"
            "**Unnecessary HTTP Methods:** If DELETE and PUT are enabled on collections, "
            "CSRF or BFLA attacks can destroy data.\n\n"
            "**TLS Downgrade:** Missing HSTS headers allow network attackers to "
            "strip HTTPS and read or modify traffic in transit.\n\n"
            "**Business Impact:** Credential exposure, data leakage, facilitates "
            "further exploitation of all other vulnerabilities."
        ),
        "references": [
            {"title": "OWASP API8:2023 Security Misconfiguration", "url": "https://owasp.org/API-Security/editions/2023/en/0xa8-security-misconfiguration/"},
            {"title": "OWASP Cheat Sheet – REST Security", "url": "https://cheatsheetseries.owasp.org/cheatsheets/REST_Security_Cheat_Sheet.html"},
            {"title": "OWASP Cheat Sheet – HTTP Security Headers", "url": "https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html"},
            {"title": "OWASP ASVS V14 – Configuration", "url": "https://owasp.org/www-project-application-security-verification-standard/"},
        ],
    },

    # ─────────────────────────────────────────────────────────────────────────
    # API9:2023 – Improper Inventory Management
    # ─────────────────────────────────────────────────────────────────────────
    {
        "id": "API9",
        "title": "API9:2023 – Improper Inventory Management",
        "short_desc": (
            "Organizations deploy multiple API versions, microservices, and third-party "
            "integrations without maintaining a complete, current inventory. Forgotten "
            "or undocumented endpoints become an unmonitored attack surface — often "
            "with weaker security than production."
        ),
        "risk_rating": "Medium",
        "vulnerable_code": {
            "Python (Flask)": """\
# BAD: v1 endpoint left active, bypasses v2 security controls
# v2 has proper rate limiting and auth; v1 does not
@app.route("/api/v1/users", methods=["GET"])   # ← old, forgotten
def list_users_v1():
    return jsonify([u.to_dict() for u in User.query.all()])

@app.route("/api/v2/users", methods=["GET"])   # ← current, secured
@jwt_required()
@limiter.limit("10 per minute")
def list_users_v2():
    ...
""",
            "JavaScript (Express)": """\
// BAD: Debug endpoint never removed from production
app.get('/api/debug/dump-db', async (req, res) => {
  // Was added during development, never deleted
  const everything = await db.query('SELECT * FROM users');
  res.json(everything);
});
""",
            "Java (Spring Boot)": """\
// BAD: Staging-only endpoint deployed to production
@GetMapping("/api/internal/reset-data")
// This endpoint should only exist in the staging profile
// Missing: @Profile("staging")
public ResponseEntity<Void> resetTestData() {
    userRepository.deleteAll();
    seedService.populateTestData();
    return ResponseEntity.noContent().build();
}
""",
            "Go": """\
// BAD: Undocumented test endpoint in production binary
func RegisterRoutes(r *gin.Engine) {
    r.GET("/api/v1/products", GetProducts)
    // Left from load testing — no auth, no rate limit
    r.DELETE("/api/test/wipe", WipeDatabase)
}
""",
            "PHP (Laravel)": """\
// BAD: Old API version still registered
Route::prefix('api/v1')->group(function () {
    // v1 — no auth, no rate limit — should have been deprecated
    Route::get('/users', [UserController::class, 'indexV1']);
});

Route::prefix('api/v2')->middleware(['auth:sanctum', 'throttle:60,1'])->group(function () {
    Route::get('/users', [UserController::class, 'indexV2']);
});
""",
        },
        "secure_code": {
            "Python (Flask)": """\
# GOOD: Proper deprecation cycle + remove old versions
# Step 1: Add deprecation notice to v1 responses
@app.route("/api/v1/users")
def list_users_v1():
    resp = jsonify({"error": "API v1 is deprecated. Use /api/v2/users"})
    resp.status_code = 410   # Gone
    resp.headers["Sunset"] = "Sat, 01 Jan 2025 00:00:00 GMT"
    return resp

# Step 2: Remove the route entirely in the next release
# Step 3: Document all active endpoints in OpenAPI spec
""",
            "JavaScript (Express)": """\
// GOOD: Remove debug endpoints; use environment guards
if (process.env.NODE_ENV !== 'production') {
  app.get('/api/debug/dump-db', async (req, res) => {
    const everything = await db.query('SELECT * FROM users');
    res.json(everything);
  });
}
// Better: don't commit debug routes at all — use proper test fixtures
""",
            "Java (Spring Boot)": """\
// GOOD: Profile-restrict internal endpoints
@Profile("!production")   // only active in non-production profiles
@GetMapping("/api/internal/reset-data")
public ResponseEntity<Void> resetTestData() {
    userRepository.deleteAll();
    seedService.populateTestData();
    return ResponseEntity.noContent().build();
}
""",
            "Go": """\
// GOOD: Test routes behind build tag or env check
func RegisterRoutes(r *gin.Engine) {
    r.GET("/api/v1/products", GetProducts)
    if os.Getenv("ENABLE_TEST_ROUTES") == "true" {
        r.DELETE("/api/test/wipe", WipeDatabase)  // never set in production
    }
}
""",
            "PHP (Laravel)": """\
// GOOD: Gate old versions, document sunset date
Route::prefix('api/v1')->group(function () {
    Route::get('/users', function () {
        return response()->json(['error' => 'API v1 deprecated'], 410)
               ->header('Sunset', 'Sat, 01 Jan 2025 00:00:00 GMT');
    });
});

Route::prefix('api/v2')
     ->middleware(['auth:sanctum', 'throttle:60,1'])
     ->group(function () {
    Route::get('/users', [UserController::class, 'index']);
});
""",
        },
        "curl_attacks": [
            {
                "title": "Discover old API versions via common paths",
                "command": (
                    "# Enumerate common API versioning patterns\n"
                    "for VER in v1 v2 v3 v1.1 v1.0 beta internal test debug; do\n"
                    "  STATUS=$(curl -s -o /dev/null -w '%{http_code}' \\\n"
                    "    https://api.example.com/api/$VER/users)\n"
                    "  echo \"$VER: $STATUS\"\n"
                    "done"
                ),
                "explanation": "Old versions with weaker or missing auth controls respond with 200 while the current version returns 401/403.",
            },
            {
                "title": "Exploit forgotten debug endpoint",
                "command": (
                    "curl https://api.example.com/api/debug/dump-db\n"
                    "# Returns full user table with hashed passwords, emails, PII"
                ),
                "explanation": "Debug endpoints left in production often have no authentication and expose the entire database.",
            },
        ],
        "propagation": (
            "**Shadow APIs:** Microservices, mobile backends, and partner integrations "
            "often have endpoints not tracked in the central API inventory. Security "
            "reviews and WAF rules miss them.\n\n"
            "**Version Bypass:** Old API versions lack rate limiting, authentication, "
            "and input validation added to newer versions — providing a clean attack path.\n\n"
            "**Debug Endpoints:** Development-only endpoints (dump-db, reset-data) "
            "that reach production can destroy data or expose full datasets.\n\n"
            "**Third-Party Risk:** APIs consumed from vendors may have different security "
            "postures; changes go unnoticed without inventory monitoring.\n\n"
            "**Business Impact:** Undetected breaches, compliance gaps, persistent "
            "attacker access via forgotten backdoors."
        ),
        "references": [
            {"title": "OWASP API9:2023 Improper Inventory Management", "url": "https://owasp.org/API-Security/editions/2023/en/0xa9-improper-inventory-management/"},
            {"title": "OWASP Cheat Sheet – REST Security", "url": "https://cheatsheetseries.owasp.org/cheatsheets/REST_Security_Cheat_Sheet.html"},
            {"title": "OWASP ASVS V1 – Architecture", "url": "https://owasp.org/www-project-application-security-verification-standard/"},
        ],
    },

    # ─────────────────────────────────────────────────────────────────────────
    # API10:2023 – Unsafe Consumption of APIs
    # ─────────────────────────────────────────────────────────────────────────
    {
        "id": "API10",
        "title": "API10:2023 – Unsafe Consumption of APIs",
        "short_desc": (
            "Developers often trust third-party APIs unconditionally, without validating "
            "their responses, enforcing TLS, or sanitizing data before further processing "
            "or storage. A compromised or malicious third-party API can inject malicious "
            "data into your application, leading to injection, data corruption, or SSRF."
        ),
        "risk_rating": "Medium",
        "vulnerable_code": {
            "Python (Flask)": """\
# BAD: Trusts third-party API response without validation
import requests

@app.route("/api/v1/enrich-user", methods=["POST"])
@jwt_required()
def enrich_user():
    email = request.json["email"]
    # Fetch from a third-party enrichment service (e.g., clearbit)
    ext = requests.get(f"https://person.clearbit.com/v2/combined/find?email={email}",
                       auth=("sk_live_key", "")).json()
    # BAD: Directly use values from external response in a SQL query
    user = User.query.filter_by(email=email).first()
    user.company = ext["company"]["name"]        # ← no validation
    user.phone = ext["person"]["phone"]          # ← could be injected payload
    db.session.commit()
    return jsonify({"ok": True})
""",
            "JavaScript (Express)": """\
// BAD: No TLS verification, no response schema validation
const axios = require('axios');

app.post('/api/v1/payment/process', authenticate, async (req, res) => {
  // BAD: Disable TLS cert check — allows MITM
  const client = axios.create({ httpsAgent: new https.Agent({ rejectUnauthorized: false }) });
  const result = await client.post('https://payment-gateway.io/charge', {
    amount: req.body.amount,
    card: req.body.card,
  });
  // BAD: Trust redirect URL from payment gateway without validation
  res.redirect(result.data.redirectUrl);   // ← open redirect via third party
});
""",
            "Java (Spring Boot)": """\
// BAD: No response validation, no timeout
@PostMapping("/api/v1/geocode")
public ResponseEntity<Address> geocode(@RequestBody Map<String, String> body) {
    String address = body.get("address");
    // BAD: No timeout, no TLS pinning, no response size limit
    ResponseEntity<Map> geoResp = restTemplate.getForEntity(
        "https://api.geocoding-service.com/json?address=" + address, Map.class);
    // BAD: Directly use unvalidated response field in HTML output (XSS risk)
    String formattedAddress = (String) geoResp.getBody().get("formatted_address");
    return ResponseEntity.ok(new Address(address, formattedAddress));
}
""",
            "Go": """\
// BAD: No TLS verification, response piped directly to DB
func EnrichUser(c *gin.Context) {
    email := c.PostForm("email")
    tr := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}} // ← MITM
    client := &http.Client{Transport: tr}
    resp, _ := client.Get("https://enrichment.api.io/find?email=" + email)
    var data map[string]interface{}
    json.NewDecoder(resp.Body).Decode(&data)
    // Pipe unvalidated external data into DB
    db.Exec("UPDATE users SET company = ? WHERE email = ?", data["company"], email)
    c.JSON(200, gin.H{"ok": true})
}
""",
            "PHP (Laravel)": """\
// BAD: Trusts third-party webhook without signature validation
public function webhook(Request $request)
{
    $payload = $request->json()->all();  // ← no HMAC signature check
    // BAD: use unvalidated payload data to update user
    $user = User::where('email', $payload['email'])->first();
    $user->update(['plan' => $payload['plan']]);  // attacker can forge this
    return response()->json(['ok' => true]);
}
""",
        },
        "secure_code": {
            "Python (Flask)": """\
# GOOD: Validate response schema, sanitize before storage
import requests
from pydantic import BaseModel, validator
import re

class EnrichmentResult(BaseModel):
    company_name: str
    phone: str

    @validator("company_name")
    def sanitize_company(cls, v):
        if len(v) > 255 or not re.match(r'^[\\w\\s,.-]+$', v):
            raise ValueError("Invalid company name")
        return v

    @validator("phone")
    def sanitize_phone(cls, v):
        if not re.match(r'^\\+?[\\d\\s()-]{7,20}$', v):
            raise ValueError("Invalid phone number")
        return v

@app.route("/api/v1/enrich-user", methods=["POST"])
@jwt_required()
def enrich_user():
    email = request.json["email"]
    resp = requests.get(
        "https://person.clearbit.com/v2/combined/find",
        params={"email": email},
        auth=("sk_live_key", ""),
        timeout=5,                      # ← always set a timeout
        verify=True,                    # ← enforce TLS (default, explicit for clarity)
    )
    resp.raise_for_status()
    data = resp.json()
    # Validate and sanitize the external response
    enriched = EnrichmentResult(
        company_name=data.get("company", {}).get("name", ""),
        phone=data.get("person", {}).get("phone", ""),
    )
    user = User.query.filter_by(email=email).first()
    user.company = enriched.company_name
    user.phone = enriched.phone
    db.session.commit()
    return jsonify({"ok": True})
""",
            "JavaScript (Express)": """\
// GOOD: TLS enforced, schema validation, no open redirect
const Joi = require('joi');

const paymentResponseSchema = Joi.object({
  transactionId: Joi.string().alphanum().max(64).required(),
  status: Joi.string().valid('success', 'failed', 'pending').required(),
  redirectUrl: Joi.string().uri({ scheme: 'https' }).required(),
});

app.post('/api/v1/payment/process', authenticate, async (req, res) => {
  const response = await axios.post('https://payment-gateway.io/charge', {
    amount: req.body.amount, card: req.body.card,
  }); // axios enforces TLS by default

  const { error, value } = paymentResponseSchema.validate(response.data);
  if (error) return res.status(502).json({ error: 'Invalid gateway response' });

  // Validate redirect is to expected domain
  const allowed = new URL('https://payment-gateway.io');
  const redirect = new URL(value.redirectUrl);
  if (redirect.hostname !== allowed.hostname)
    return res.status(502).json({ error: 'Unexpected redirect' });

  res.redirect(value.redirectUrl);
});
""",
            "Java (Spring Boot)": """\
// GOOD: Validate response, set timeouts, sanitize
@PostMapping("/api/v1/geocode")
public ResponseEntity<Address> geocode(@RequestBody @Valid GeoRequest body) {
    RestTemplate rt = new RestTemplateBuilder()
        .setConnectTimeout(Duration.ofSeconds(3))
        .setReadTimeout(Duration.ofSeconds(5))
        .build();
    ResponseEntity<GeoResponse> geoResp = rt.getForEntity(
        "https://api.geocoding-service.com/json?address={addr}",
        GeoResponse.class, body.getAddress());

    String formatted = sanitize(geoResp.getBody().getFormattedAddress()); // HTML-escape
    return ResponseEntity.ok(new Address(body.getAddress(), formatted));
}
""",
            "Go": """\
// GOOD: TLS enforced, timeout, response validation
func EnrichUser(c *gin.Context) {
    email := c.PostForm("email")
    client := &http.Client{Timeout: 5 * time.Second} // no InsecureSkipVerify
    resp, err := client.Get("https://enrichment.api.io/find?email=" + url.QueryEscape(email))
    if err != nil { c.JSON(502, gin.H{"error": "upstream error"}); return }
    defer resp.Body.Close()
    body := io.LimitReader(resp.Body, 1<<20) // max 1MB
    var data EnrichmentResponse
    if err := json.NewDecoder(body).Decode(&data); err != nil {
        c.JSON(502, gin.H{"error": "invalid upstream response"}); return
    }
    // Validate fields before storage
    if !isValidCompanyName(data.Company) {
        c.JSON(502, gin.H{"error": "invalid data from upstream"}); return
    }
    db.Exec("UPDATE users SET company = ? WHERE email = ?", data.Company, email)
    c.JSON(200, gin.H{"ok": true})
}
""",
            "PHP (Laravel)": """\
// GOOD: Verify HMAC signature before processing webhook
public function webhook(Request $request)
{
    $secret = config('services.payment.webhook_secret');
    $signature = $request->header('X-Signature');
    $computed = hash_hmac('sha256', $request->getContent(), $secret);
    if (!hash_equals($computed, $signature)) {
        return response()->json(['error' => 'Invalid signature'], 401);
    }
    $payload = $request->json()->all();
    $request->validate(['email' => 'required|email', 'plan' => 'required|in:free,pro,enterprise']);
    $user = User::where('email', $payload['email'])->firstOrFail();
    $user->update(['plan' => $payload['plan']]);
    return response()->json(['ok' => true]);
}
""",
        },
        "curl_attacks": [
            {
                "title": "Forge a webhook payload (no signature check)",
                "command": (
                    "curl -X POST https://api.example.com/api/v1/payment/webhook \\\n"
                    "  -H 'Content-Type: application/json' \\\n"
                    "  -d '{\"email\":\"victim@example.com\",\"plan\":\"enterprise\",\"status\":\"success\"}'"
                ),
                "explanation": "Without HMAC signature verification the attacker can forge any event — upgrading accounts, faking payments.",
            },
            {
                "title": "MITM third-party API to inject malicious data",
                "command": (
                    "# Simulate a compromised enrichment API returning injection payload\n"
                    "# The API returns:\n"
                    "# {\"company\": \"Acme'); DROP TABLE users; --\", \"phone\": \"<script>alert(1)</script>\"}\n"
                    "# If the consumer doesn't validate, this gets stored in the DB."
                ),
                "explanation": "A compromised or malicious upstream API injects SQL/XSS payloads that get stored and later served to other users.",
            },
        ],
        "propagation": (
            "**Supply-Chain Attack:** A compromised third-party API becomes an injection "
            "vector into your database, cache, or downstream services without any "
            "direct attacker access to your API.\n\n"
            "**Stored XSS:** Unsanitized strings from external APIs stored in the DB "
            "are later returned to other users' browsers, executing malicious JavaScript.\n\n"
            "**SQL Injection via Third Party:** If response values are interpolated into "
            "raw queries, a compromised upstream provider can drop tables or exfiltrate data.\n\n"
            "**Webhook Forgery:** Without signature verification, any party knowing the "
            "endpoint URL can forge business events (payment confirmations, plan upgrades).\n\n"
            "**TLS Downgrade / MITM:** Disabling certificate verification allows "
            "network attackers to intercept and alter traffic between your API and "
            "third-party services.\n\n"
            "**Business Impact:** Data corruption, stored XSS at scale, financial fraud "
            "via forged payment events, full system compromise via supply chain."
        ),
        "references": [
            {"title": "OWASP API10:2023 Unsafe Consumption of APIs", "url": "https://owasp.org/API-Security/editions/2023/en/0xaa-unsafe-consumption-of-apis/"},
            {"title": "OWASP Cheat Sheet – Input Validation", "url": "https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html"},
            {"title": "OWASP Cheat Sheet – Third Party JavaScript Management", "url": "https://cheatsheetseries.owasp.org/cheatsheets/Third_Party_Javascript_Management_Cheat_Sheet.html"},
            {"title": "OWASP ASVS V11 – Business Logic", "url": "https://owasp.org/www-project-application-security-verification-standard/"},
        ],
    },
]
