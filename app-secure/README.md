# 🔒 Secure JWT Application

## 📋 Detailed Steps to Test Security

---

### Step 1: Install Dependencies

```bash
# Navigate to the secure app folder
cd app-secure

# Install all required dependencies
npm install
✅ Verification: The node_modules folder should be created.

Step 2: Start the Secure Application
bash
Copier le code
# Start the secure server
npm start
🟢 Expected confirmation messages:
markdown
Copier le code
🔒 SECURE APPLICATION STARTED
📍 URL: http://localhost:3002

🛡️  SECURITY MEASURES ENABLED:
   1. HS256 algorithm only
   2. Strong secrets + environment variables
   3. Short expiration (15 minutes)
   4. Minimal secure payload
   5. Cryptographic verification
   6. Rate limiting anti-brute-force
   7. Role-based access control
   8. Token blacklist support
🧪 Step 3: Test with Postman (FULL SEQUENCE)
🟢 Test 3.1: Check Application Status
METHOD: GET

URL: http://localhost:3002/health

No special headers required

Expected response:

json
Copier le code
{
  "status": "healthy",
  "security": "enabled",
  "features": [
    "Rate Limiting (5 req/15min)",
    "Token Expiration (15 minutes)",
    "Algorithm Validation (HS256 only)",
    "Input Sanitization",
    "Role-Based Access Control",
    "Token Blacklisting"
  ]
}
🟢 Test 3.2: User Login (Normal)
METHOD: POST

URL: http://localhost:3002/login

Headers: Content-Type: application/json

Body:

json
Copier le code
{
    "username": "alice",
    "password": "pass123"
}
Expected response:

json
Copier le code
{
  "message": "Login successful!",
  "accessToken": "eyJhbGciOiJIUzI1Ni...",
  "expiresIn": "15m",
  "user": {
    "id": 1,
    "username": "alice",
    "role": "user"
  }
}
💡 Copy the token for the next tests.

🟢 Test 3.3: Access Profile (Should WORK)
METHOD: GET

URL: http://localhost:3002/profile

Headers:

pgsql
Copier le code
Content-Type: application/json
Authorization: Bearer [PASTE_YOUR_TOKEN_HERE]
Expected response:

json
Copier le code
{
  "message": "User profile",
  "user": {
    "userId": 1,
    "username": "alice",
    "role": "user",
    "iat": 1763323749,
    "exp": 1763324649
  },
  "security": {
    "verified": true,
    "algorithm": "HS256",
    "expiration": "2025-01-20T12:50:49.000Z"
  }
}
🔍 Note: No sensitive data, includes expiration.

🔴 Test 3.4: Admin Access Attempt (Should FAIL)
METHOD: GET

URL: http://localhost:3002/admin

Headers:

pgsql
Copier le code
Content-Type: application/json
Authorization: Bearer [SAME_USER_TOKEN]
Expected response (403):

json
Copier le code
{
  "error": "Insufficient permissions",
  "message": "Access denied: admin role required",
  "yourRole": "user"
}
🔴 Test 3.5: "None" Algorithm Attack (Should FAIL)
METHOD: POST

URL: http://localhost:3002/verify

Headers: Content-Type: application/json

Body:

json
Copier le code
{
    "token": "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJ1c2VySWQiOjk5OSwidXNlcm5hbWUiOiJoYWNrZXIiLCJyb2xlIjoiYWRtaW4iLCJpYXQiOjE3NjMzMjM3NDl9."
}
Expected response (401):

json
Copier le code
{
  "valid": false,
  "error": "Token verification failed",
  "details": "invalid algorithm"
}
🟢 Test 3.6: Admin Login (For Comparison)
METHOD: POST

URL: http://localhost:3002/login

Body:

json
Copier le code
{
    "username": "admin",
    "password": "admin123"
}
Expected response:
Successfully receive a token with role "admin".
Use it to access /admin – it should WORK. Compare structures with the user token — only the role differs.

🚀 Step 4: Automated Security Tests
bash
Copier le code
# From the app-secure directory
node test-security.js
Expected output:

sql
Copier le code
🔒 SECURITY TEST - Secure Application

1️⃣ Normal login test...
✅ Login successful

2️⃣ Algorithm "none" attack...
✅ SECURE: "none" algorithm rejected

3️⃣ Admin access attempt with user token...
✅ SECURE: Admin access denied for user token

🎯 ALL SECURITY TESTS PASSED!
🔍 Step 5: Advanced Security Tests
🔴 Test 5.1: Rate Limiting (after 5 attempts)
Try 6 consecutive wrong login attempts:

Attempts 1–5: Normal 401 Unauthorized

Attempt 6: ❌ Error 429 — Rate limit enforced

🔴 Test 5.2: Modified Token
Take a valid token

Edit part of the payload

Try accessing /profile — Should FAIL

🟢 Test 5.3: Logout (Token Revocation)
METHOD: POST

URL: http://localhost:3002/logout

Headers: Authorization: Bearer [VALID_TOKEN]

Expected response: Logout successful

🔴 Try using the same token again → Should FAIL

👤 Available Test Accounts
Type	Username	Password
Normal user	alice	pass123
Administrator	admin	admin123

🛡️ Security Features Verified
Feature	Test Passed
HS256 only	"None" attack rejected
15-minute expiration	Expired token rejected
Minimal payload	No sensitive data leaked
Cryptographic verification	Modified token rejected
Rate limiting	Brute-force blocked
Role-based access control	User ≠ Admin
Token blacklist support	Logout effective

⚠️ Troubleshooting
Issue: "Port 3002 already in use"
Solution:

bash
Copier le code
# Kill the process using the port
npx kill-port 3002

# Or start the app on a different port
PORT=3003 npm start
Issue: Dependency errors
Solution:

bash
Copier le code
rm -rf node_modules package-lock.json
npm install
🎯 Final Result
All attacks that worked on the vulnerable version should now FAIL on the secure application! 🔒

Security is preserved without sacrificing functionality for legitimate users. ✔️

Copier le code
