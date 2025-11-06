# 🏦 NexusPay API — Secure Payment Gateway

# Members

* Dean ST10326084
* Matthew
* Musa
* Fortune 






### 📘 About This Project

NexusPay API is a **Node.js backend service** that simulates a secure international payment system. It was built to meet **INSY3D Task 2 security requirements** and demonstrates industry-standard practices such as:

* Encrypted data transmission (TLS 1.3)
* Password hashing using **Argon2id**
* **AES-256-GCM** encryption for sensitive data
* **JWT authentication** for secure user access
* Multi-step **payment workflow** (Draft → Verify → SWIFT)

It’s designed to look, act, and perform like a real enterprise API used by financial institutions, with clear documentation so that any marker or reviewer can easily follow the logic.

---

## 🎯 Purpose

This API simulates how a secure banking backend would handle:

* User registration and login
* Payment creation and approval
* Beneficiary management
* Secure communication between users and staff roles

Each feature directly maps to a **security principle** outlined in the Task 2 rubric.

---

## 🧩 Key Features (Simplified)

### 🔐 Security Highlights

| Control                | Implementation                               |
| ---------------------- | -------------------------------------------- |
| **Transport Security** | TLS 1.3 enforced on all traffic              |
| **Password Storage**   | Argon2id hashing (OWASP recommended)         |
| **Data Encryption**    | AES-256-GCM envelope encryption              |
| **Attack Protection**  | Custom WAF, rate limits, validation, headers |
| **Audit Logs**         | Tamper-proof hash-chained log trail          |
| **Access Control**     | JWT-based roles for customer, staff, admin   |

### 💳 Payment Workflow

1. Customer creates a **draft payment**.
2. Adds **beneficiary details** (recipient info).
3. Submits payment for **staff verification**.
4. Staff verifies and sends it to **SWIFT** (simulated).
5. Payment is completed and logged.

### 🧑‍💼 User Roles

* **Customer** – creates and submits payments.
* **Staff** – verifies and approves or rejects payments.
* **Admin** – system-level access for auditing and monitoring.

---

## ⚙️ Setup Instructions (Step-by-Step)

### 🪜 Step 1 — Prerequisites

* [Node.js 18+](https://nodejs.org/)
* npm (comes with Node)
* SQLite (already included for development)

### 🪜 Step 2 — Installation

```bash
# Clone or open the API folder
cd node-API

# Install dependencies
npm install
```

### 🪜 Step 3 — Configure Environment

```bash
# Copy example environment file
cp env.example .env
```

Then open `.env` and set your own values (like secrets, ports, etc.).

### 🪜 Step 4 — Generate SSL Certificates (REQUIRED)

Follow the exact process in `SETUP_SSL_DEV.md`.

```powershell
# From node-API directory
cd node-API
npm run ssl:generate
```

The script will print the precise `.env` lines with ABSOLUTE PATHS, e.g.:

```
Add these to your .env file:

# SSL/TLS Configuration (Development)
TLS_CERT_PATH=C:\Users\musan\OneDrive - ADvTECH Ltd\Nexus\node-API\certs\server.pem
TLS_KEY_PATH=C:\Users\musan\OneDrive - ADvTECH Ltd\Nexus\node-API\certs\server.key
TLS_CA_PATH=C:\Users\musan\OneDrive - ADvTECH Ltd\Nexus\node-API\certs\server.pem
```

Copy those lines exactly into `node-API/.env` (absolute paths are required on Windows).

Start the server and open:
`https://localhost:5118/health`

Your browser will warn about the self‑signed cert. For development, click:
Advanced → Proceed to localhost (unsafe).

More details and troubleshooting: `SETUP_SSL_DEV.md`.

### 🪜 Step 5 — Setup Database

```bash
# Generate Prisma client
npx prisma generate

# Create and migrate database
npx prisma db push

# Optional: seed test data
npm run db:seed
```

### 🪜 Step 6 — Run the Server

```bash
# Start in development mode
npm run dev

# Or build and run in production
npm run build
npm start
```

### 🪜 Step 7 — Test It Works

Check health endpoint:

```bash
curl -k https://localhost:5118/health
```

If setup was successful, you’ll see:

```json
{"success":true,"message":"NexusPay API is healthy"}
```

---

## 🧠 How It Works (Simplified Logic)

### 1️⃣ Registration & Login

Users register with their **email, account number, and password**. Passwords are hashed using **Argon2id** before storage. On login, they receive a **JWT access token**.

### 2️⃣ JWT Authentication

* Access tokens expire in 15 minutes.
* Refresh tokens are valid for 7 days.
* Every API call checks for a valid token before access.

### 3️⃣ Payments

Each payment moves through clear stages:

```
Draft → Pending Verification → Verified → Submitted to SWIFT → Completed
```

All changes are **logged and hashed** to create an immutable audit trail.

### 4️⃣ Beneficiaries

Customers can create and manage recipients. All details (like account numbers and addresses) are **encrypted** using AES-256-GCM.

---

## 📂 Folder Layout (Simplified)

```
Api/
├── src/
│   ├── controllers/    # Handles API requests
│   ├── services/       # Core business logic
│   ├── middleware/     # Authentication, validation, errors
│   ├── routes/         # API endpoint definitions
│   ├── validators/     # Input validation schemas
│   └── server.ts       # Application entry point
│
├── prisma/             # Database schema & files
├── logs/               # Audit, security & error logs
├── env.example          # Sample configuration
└── README.md           # This file
```

---

## 🧾 Example API Usage

### ✅ Register User

```http
POST /api/v1/auth/register
{
  "fullName": "John Doe",
  "email": "john@example.com",
  "accountNumber": "12345678",
  "password": "SecurePass123!"
}
```

### ✅ Login User

```http
POST /api/v1/auth/login
{
  "usernameOrEmail": "john@example.com",
  "password": "SecurePass123!"
}
```

### ✅ Create Payment Draft

```http
POST /api/v1/payments
Authorization: Bearer <access_token>
{
  "amount": 1000.00,
  "currency": "USD",
  "reference": "INV-2025-001",
  "purpose": "Business payment"
}
```

### ✅ Staff Verification

```http
POST /api/v1/payments/{id}/verify
Authorization: Bearer <staff_token>
{
  "action": "approve"
}
```

---

## 🔒 Security Breakdown (for Task 2 Marking)

| Category              | Implementation      | Description                              |
| --------------------- | ------------------- | ---------------------------------------- |
| **Encryption**        | AES-256-GCM         | Field-level encryption for PII           |
| **Hashing**           | Argon2id            | Passwords hashed, never stored plaintext |
| **Authentication**    | JWT                 | Short-lived tokens, refreshable          |
| **Transport Layer**   | TLS 1.3             | Encrypts all network traffic             |
| **Audit Logging**     | Hash-chained        | Every event linked for tamper detection  |
| **Attack Prevention** | WAF + Rate limiting | Stops brute-force and spam attacks       |

---

## 🧪 Testing Credentials

These are seeded for easy testing:

```
Customer: customer@nexuspay.dev / Customer123!
Staff:    staff@nexuspay.dev / Staff123!
Admin:    admin@nexuspay.dev / Admin123!
```

You can test using any API client (Postman, Insomnia, or `curl`).

---

## 📈 Deployment (Simplified)

For marking and local testing, run locally.
For production-like testing:

```bash
docker build -t nexuspay-api .
docker run -p 5118:5118 nexuspay-api
```

---

## 🧾 Summary for Markers

This project demonstrates:

* Secure backend design using Node.js + TypeScript
* Full implementation of Task 2 security principles
* Clear payment flow and audit logging
* Comprehensive documentation and setup steps

It can be cloned, installed, and tested in under 10 minutes.

