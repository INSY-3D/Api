# NexusPay API - Enterprise Payment Gateway

[![Node.js](https://img.shields.io/badge/Node.js-18+-green.svg)](https://nodejs.org/)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.8-blue.svg)](https://www.typescriptlang.org/)
[![Express](https://img.shields.io/badge/Express-4.21-lightgrey.svg)](https://expressjs.com/)
[![Prisma](https://img.shields.io/badge/Prisma-6.6-2D3748.svg)](https://www.prisma.io/)
[![Security](https://img.shields.io/badge/Security-Task_2_Compliant-brightgreen.svg)]()

A secure, enterprise-grade Node.js API for international payment processing with full Task 2 compliance, email-based OTP authentication, and SWIFT network integration.

---

## 🎯 Overview

NexusPay API is a production-ready backend service that handles secure international payments through the SWIFT network. It features comprehensive security controls, email-based multi-factor authentication, field-level encryption, immutable audit logging, and role-based access control for both customers and staff members.

---

## ✨ Key Features

### 🔐 Security & Compliance

#### **Task 2 Full Compliance**
- ✅ **TLS 1.3 Only** - All traffic encrypted with latest TLS protocol
- ✅ **Argon2id Password Hashing** - Industry-leading password security (OWASP recommended)
- ✅ **PII Encryption at Rest** - AES-256-GCM envelope encryption for sensitive data
- ✅ **Input Validation** - Server-side regex allowlist validation with Zod
- ✅ **Attack Protections** - Custom WAF, rate limiting, security headers
- ✅ **Immutable Audit Logging** - Tamper-evident audit trails with hashing
- ✅ **Multi-step Payment Workflow** - Draft → Beneficiary → Submit → Verify → SWIFT
- ✅ **SWIFT Integration Ready** - mTLS connectivity for production

#### **Authentication & Authorization**
- **Email-based OTP** - One-time passwords sent via SMTP for customer login
- **Flexible OTP delivery** - Supports registered email or manual email entry
- **10-minute OTP expiry** - Time-limited codes with automatic cleanup
- **Staff OTP bypass** - Staff and admin roles skip OTP for efficiency
- **JWT tokens** - HS256 signed access and refresh tokens
- **Token refresh** - Automatic access token renewal
- **Session management** - Failed login attempt tracking and account lockout
- **Device tracking** - Unknown device detection (future MFA trigger)

#### **Encryption**
- **Master key management** - Envelope encryption with master DEK
- **Field-level encryption** - PII fields encrypted individually
- **AES-256-GCM** - Authenticated encryption with additional data (AEAD)
- **Nonce handling** - Proper IV/nonce generation per encryption
- **Key rotation ready** - Multi-key infrastructure for zero-downtime rotation

#### **Security Controls**
- **Web Application Firewall (WAF)** - Detects and blocks common attacks
  - SQL injection prevention
  - XSS attack blocking
  - Path traversal protection
  - Command injection detection
  - LDAP injection prevention
- **Rate Limiting** - Request throttling per endpoint
  - General API: 100 req/15 min
  - Login: 5 attempts/15 min
  - Registration: 3 attempts/hour
  - WAF: 1000 req/min
- **Security Headers** - Comprehensive HTTP security headers
  - Content Security Policy (CSP)
  - HTTP Strict Transport Security (HSTS)
  - X-Frame-Options: DENY
  - X-Content-Type-Options: nosniff
  - Referrer-Policy: strict-origin-when-cross-origin
- **CSRF Protection** - Token-based cross-site request forgery prevention

### 📧 Email & OTP Services

#### **Email Delivery**
- **SMTP Support** - Nodemailer integration for production emails
- **Development Mode** - Console logging for local development
- **Multi-provider** - Supports Gmail, Brevo, Outlook, SendGrid, etc.
- **Template System** - HTML email templates with branding
- **Email masking** - Privacy-preserving email display in logs

#### **OTP Management**
- **Code generation** - Cryptographically secure 6-digit codes
- **Expiry handling** - Automatic expiration after 10 minutes
- **Previous code invalidation** - New OTP invalidates old ones
- **Purpose tracking** - Support for login, password reset, etc.
- **Cleanup service** - Automatic removal of expired codes
- **Security logging** - All OTP events logged for audit

### 💳 Payment Processing

#### **Payment Workflow**
1. **Draft Creation** - Create payment with amount and currency
2. **Beneficiary Selection** - Update with beneficiary details
3. **Customer Submission** - Submit for staff verification
4. **Staff Verification** - Approve or reject payment
5. **SWIFT Submission** - Submit to SWIFT network
6. **Completion** - Mark as completed after settlement

#### **Payment Features**
- **Draft management** - Save and edit before submission
- **Idempotency** - Duplicate prevention with idempotency keys
- **Reference tracking** - Custom payment references (35 chars max)
- **Purpose description** - Payment purpose (140 chars max)
- **Multi-currency** - Support for multiple currencies (USD, EUR, GBP, ZAR, etc.)
- **SWIFT/BIC validation** - Real-time bank code validation
- **IBAN support** - International Bank Account Number validation
- **Status tracking** - Comprehensive status progression
- **Customer visibility** - Staff can see customer details for support

#### **Beneficiary Management**
- **CRUD operations** - Create, read, update, delete beneficiaries
- **Saved beneficiaries** - Store frequently used recipients
- **Validation** - SWIFT/BIC, IBAN, and address validation
- **Privacy** - Encrypted storage of beneficiary PII
- **User isolation** - Users can only access their own beneficiaries

### 📊 Logging & Monitoring

#### **Structured Logging (Winston)**
- **Multiple log files** - Separated by concern
  - `combined.log` - All application logs
  - `error.log` - Error-level events only
  - `security.log` - Security-related events
  - `audit.log` - Immutable audit trail
  - `performance.log` - Performance metrics
  - `exceptions.log` - Uncaught exceptions
  - `rejections.log` - Unhandled promise rejections
- **Log rotation** - Automatic archival and cleanup
- **Structured format** - JSON for easy parsing
- **Context enrichment** - User ID, IP, user agent in all logs

#### **Security Events**
- **Login events** - Successful and failed login attempts
- **OTP events** - Generation, verification, expiration
- **Payment events** - Creation, submission, verification
- **Access events** - Unauthorized access attempts
- **Admin actions** - All privileged operations
- **Risk levels** - LOW, MEDIUM, HIGH, CRITICAL classification

#### **Audit Trail**
- **Immutable logging** - Tamper-evident audit records
- **Hash chaining** - Each record hashes with previous
- **Compliance ready** - Meets regulatory requirements
- **Event types** - Comprehensive event enumeration
- **Retention** - Configurable retention policies

---

## 🚀 Tech Stack

### **Core Framework**
- **Node.js 18+** - Modern JavaScript runtime
- **TypeScript 5.8** - Type-safe development
- **Express 4.21** - Web application framework
- **ts-node** - TypeScript execution for development

### **Database & ORM**
- **Prisma 6.6** - Next-generation ORM
- **SQLite** - Development database
- **PostgreSQL/MySQL** - Production database support
- **Migration system** - Version-controlled schema changes

### **Security**
- **Argon2** - Password hashing (argon2id variant)
- **jsonwebtoken** - JWT token generation and validation
- **crypto (Node.js)** - Encryption and hashing
- **express-rate-limit** - Request rate limiting
- **helmet** - Security headers middleware

### **Email & Communication**
- **Nodemailer** - Email sending library
- **SMTP** - Standard email protocol support
- **HTML templates** - Rich email formatting

### **Validation & Sanitization**
- **Zod** - TypeScript-first schema validation
- **Custom validators** - SWIFT/BIC, IBAN, etc.
- **Regex allowlists** - Whitelist-based input filtering

### **Logging & Monitoring**
- **Winston** - Comprehensive logging framework
- **winston-daily-rotate-file** - Log rotation
- **Performance APIs** - Built-in performance tracking

---

## 📂 Project Structure

```
Api/
├── src/
│   ├── config/                     # Configuration
│   │   ├── database.ts             # Prisma client setup
│   │   ├── logger.ts               # Winston logger configuration
│   │   └── index.ts                # Environment config
│   │
│   ├── controllers/                # Request handlers
│   │   ├── auth.controller.ts      # Authentication endpoints
│   │   ├── payment.controller.ts   # Payment endpoints
│   │   └── beneficiary.controller.ts # Beneficiary endpoints
│   │
│   ├── services/                   # Business logic
│   │   ├── auth.service.ts         # Authentication logic
│   │   ├── payment.service.ts      # Payment processing
│   │   ├── beneficiary.service.ts  # Beneficiary management
│   │   ├── encryption.service.ts   # Encryption utilities
│   │   ├── email.service.ts        # Email sending
│   │   └── otp.service.ts          # OTP management
│   │
│   ├── middleware/                 # Express middleware
│   │   ├── auth.middleware.ts      # JWT authentication
│   │   ├── validation.middleware.ts # Input validation
│   │   ├── security.middleware.ts  # WAF and security
│   │   ├── error.middleware.ts     # Error handling
│   │   └── notFound.middleware.ts  # 404 handling
│   │
│   ├── routes/                     # API routes
│   │   ├── auth.routes.ts          # /api/v1/auth/*
│   │   ├── payment.routes.ts       # /api/v1/payments/*
│   │   └── beneficiary.routes.ts   # /api/v1/beneficiaries/*
│   │
│   ├── validators/                 # Zod schemas
│   │   ├── auth.validators.ts      # Auth input validation
│   │   ├── payment.validators.ts   # Payment validation
│   │   └── beneficiary.validators.ts # Beneficiary validation
│   │
│   ├── types/                      # TypeScript types
│   │   ├── index.ts                # DTOs and interfaces
│   │   └── enums.ts                # Enumerations
│   │
│   ├── scripts/                    # Utility scripts
│   │   ├── seed.ts                 # Database seeding
│   │   └── cleanup.ts              # Maintenance tasks
│   │
│   └── server.ts                   # Application entry point
│
├── prisma/
│   ├── schema.prisma               # Database schema
│   └── nexuspay.db                 # SQLite database (dev)
│
├── logs/                           # Log files
│   ├── combined.log                # All logs
│   ├── error.log                   # Errors only
│   ├── security.log                # Security events
│   ├── audit.log                   # Audit trail
│   └── performance.log             # Performance metrics
│
├── dist/                           # Compiled JavaScript
├── env.example                     # Example environment file
├── package.json                    # Dependencies and scripts
├── tsconfig.json                   # TypeScript config
└── README.md                       # This file
```

---

## 🔧 Installation & Setup

### **Prerequisites**
- Node.js 18+ (LTS recommended)
- npm 8+ or yarn 1.22+
- SQLite (included) or PostgreSQL/MySQL for production

### **Quick Start**

1. **Clone the repository**
   ```bash
   cd Api
   ```

2. **Install dependencies**
   ```bash
   npm install
   ```

3. **Environment configuration**
   ```bash
   # Copy example environment file
   cp env.example .env
   
   # Edit .env with your configuration
   nano .env
   ```

4. **Database setup**
   ```bash
   # Generate Prisma client
   npx prisma generate
   
   # Create and migrate database
   npx prisma db push
   
   # Seed with test data (optional)
   npm run db:seed
   ```

5. **Start the server**
   ```bash
   # Development mode (hot reload)
   npm run dev
   
   # Production build and start
   npm run build
   npm start
   ```

6. **Verify installation**
   ```bash
   # Check health endpoint
   curl http://localhost:5118/health
   
   # Should return: {"status":"ok","timestamp":"..."}
   ```

---

## ⚙️ Configuration

### **Environment Variables**

Create a `.env` file in the `Api` directory with the following configuration:

```env
# ============================================
# SERVER CONFIGURATION
# ============================================
NODE_ENV=development
PORT=5118
HOST=localhost
API_VERSION=v1

# ============================================
# DATABASE
# ============================================
# SQLite (Development)
DATABASE_URL="file:./prisma/nexuspay.db"

# PostgreSQL (Production)
# DATABASE_URL="postgresql://user:password@localhost:5432/nexuspay?schema=public"

# MySQL (Production)
# DATABASE_URL="mysql://user:password@localhost:3306/nexuspay"

# ============================================
# JWT AUTHENTICATION
# ============================================
JWT_SECRET="your-super-secure-jwt-secret-minimum-32-characters-required"
JWT_REFRESH_SECRET="your-super-secure-refresh-secret-minimum-32-characters-required"
JWT_EXPIRY="15m"
JWT_REFRESH_EXPIRY="7d"

# ============================================
# ENCRYPTION
# ============================================
ENCRYPTION_MASTER_KEY_ID="nexuspay-master-key-2025"
# Master key should be stored in KMS/HSM in production
# For dev, it's derived from the ID using a deterministic algorithm

# ============================================
# PASSWORD HASHING (Argon2id)
# ============================================
ARGON2_MEMORY_COST=65536      # 64 MB
ARGON2_TIME_COST=3            # 3 iterations
ARGON2_PARALLELISM=1          # 1 thread

# ============================================
# SMTP EMAIL CONFIGURATION
# ============================================
SMTP_ENABLED=true
SMTP_HOST="smtp-relay.brevo.com"
SMTP_PORT=587
SMTP_SECURE=false
SMTP_USER="your-smtp-username"
SMTP_PASS="your-smtp-password"
SMTP_FROM="NexusPay Security <noreply@nexuspay.bank>"

# Development: Set SMTP_ENABLED=false to log OTPs to console

# ============================================
# SWIFT NETWORK (Production)
# ============================================
SWIFT_BASE_URL="https://swift-gateway.nexuspay.bank"
SWIFT_SENDER_BIC="NEXUSZAJJ"
SWIFT_API_KEY="your-swift-api-key"
SWIFT_MTLS_CERT_PATH="/path/to/client-cert.pem"
SWIFT_MTLS_KEY_PATH="/path/to/client-key.pem"

# ============================================
# SECURITY
# ============================================
ALLOWED_ORIGINS="http://localhost:5173,https://nexuspay.com"
CSRF_SECRET="your-csrf-secret-key"
MAX_LOGIN_ATTEMPTS=5
LOCKOUT_DURATION=900000       # 15 minutes in milliseconds

# ============================================
# LOGGING
# ============================================
LOG_LEVEL=info               # debug, info, warn, error
LOG_MAX_SIZE=20m             # Max log file size
LOG_MAX_FILES=14d            # Log retention period

# ============================================
# RATE LIMITING
# ============================================
RATE_LIMIT_WINDOW=900000     # 15 minutes
RATE_LIMIT_MAX_REQUESTS=100
LOGIN_RATE_LIMIT=5
REGISTER_RATE_LIMIT=3
```

### **SMTP Configuration**

For email-based OTP, configure SMTP with one of these providers:

#### **Brevo (Recommended for development)**
```env
SMTP_ENABLED=true
SMTP_HOST="smtp-relay.brevo.com"
SMTP_PORT=587
SMTP_SECURE=false
SMTP_USER="your-brevo-login-email"
SMTP_PASS="your-brevo-smtp-key"
SMTP_FROM="your-verified-sender@domain.com"
```

#### **Gmail**
```env
SMTP_ENABLED=true
SMTP_HOST="smtp.gmail.com"
SMTP_PORT=587
SMTP_SECURE=false
SMTP_USER="your-email@gmail.com"
SMTP_PASS="your-app-specific-password"
SMTP_FROM="your-email@gmail.com"
```

#### **Development (Console logging)**
```env
SMTP_ENABLED=false
# OTPs will be logged to console instead of emailed
```

See `SMTP_SETUP.md` for detailed setup instructions.

---

## 📡 API Documentation

### **Base URL**
```
http://localhost:5118/api/v1
```

### **Authentication Endpoints**

#### **Register Customer**
```http
POST /api/v1/auth/register
Content-Type: application/json

{
  "fullName": "John Doe",
  "saId": "9001015009087",
  "accountNumber": "12345678",
  "email": "john@example.com",
  "password": "SecurePass123!"
}

Response 201:
{
  "success": true,
  "message": "Registration successful",
  "data": {
    "user": {
      "id": "cm...",
      "fullName": "John Doe",
      "email": "john@example.com",
      "role": "customer",
      "createdAt": "2025-01-10T..."
    },
    "accessToken": "eyJhbGc...",
    "refreshToken": "eyJhbGc...",
    "expiresIn": "15m"
  }
}
```

#### **Customer Login (with OTP)**
```http
POST /api/v1/auth/login
Content-Type: application/json

# Step 1: Initial login (triggers OTP)
{
  "usernameOrEmail": "john@example.com",
  "accountNumber": "12345678",
  "password": "SecurePass123!"
}

Response 200 (OTP Required):
{
  "success": true,
  "message": "OTP sent to your email. It expires in 10 minutes.",
  "data": {
    "mfa": "required",
    "hasEmail": true,
    "user": {
      "id": "cm...",
      "fullName": "John Doe",
      "email": "john@example.com",
      "role": "customer"
    }
  }
}

# Step 2: Submit OTP
{
  "usernameOrEmail": "john@example.com",
  "accountNumber": "12345678",
  "password": "SecurePass123!",
  "otp": "123456"
}

Response 200 (Success):
{
  "success": true,
  "message": "Login successful",
  "data": {
    "user": {...},
    "accessToken": "eyJhbGc...",
    "refreshToken": "eyJhbGc...",
    "expiresIn": "15m"
  }
}
```

#### **Send OTP (Manual)**
```http
POST /api/v1/auth/send-otp
Content-Type: application/json

{
  "email": "john@example.com",
  "userId": "cm..." // optional
}

Response 200:
{
  "success": true,
  "message": "OTP sent to jo**@example.com"
}
```

#### **Staff Login (no OTP)**
```http
POST /api/v1/auth/staff-login
Content-Type: application/json

{
  "usernameOrEmail": "staff@nexuspay.dev",
  "accountNumber": "87654321",
  "password": "Staff123!"
}

Response 200:
{
  "success": true,
  "message": "Login successful",
  "data": {
    "user": {
      "id": "cm...",
      "fullName": "Staff Member",
      "email": "staff@nexuspay.dev",
      "role": "staff"
    },
    "accessToken": "eyJhbGc...",
    "refreshToken": "eyJhbGc...",
    "expiresIn": "15m"
  }
}
```

#### **Refresh Token**
```http
POST /api/v1/auth/refresh
Content-Type: application/json

{
  "refreshToken": "eyJhbGc..."
}

Response 200:
{
  "success": true,
  "data": {
    "accessToken": "eyJhbGc...",
    "expiresIn": "15m"
  }
}
```

#### **Get Current User**
```http
GET /api/v1/auth/me
Authorization: Bearer <access_token>

Response 200:
{
  "success": true,
  "data": {
    "user": {
      "id": "cm...",
      "fullName": "John Doe",
      "email": "john@example.com",
      "role": "customer",
      "createdAt": "2025-01-10T..."
    }
  }
}
```

### **Payment Endpoints**

#### **Create Draft Payment**
```http
POST /api/v1/payments
Authorization: Bearer <access_token>
Content-Type: application/json

{
  "amount": "1000.00",
  "currency": "USD",
  "provider": "SWIFT",
  "reference": "INV-2025-001",      // optional, max 35 chars
  "purpose": "Business payment",    // optional, max 140 chars
  "idempotencyKey": "unique-uuid"   // prevents duplicates
}

Response 201:
{
  "success": true,
  "message": "Draft payment created",
  "data": {
    "id": "cm...",
    "amount": 1000.00,
    "currency": "USD",
    "status": "draft",
    "reference": "INV-2025-001",
    "purpose": "Business payment",
    "createdAt": "2025-01-10T..."
  }
}
```

#### **Update Beneficiary Details**
```http
PUT /api/v1/payments/{id}/beneficiary
Authorization: Bearer <access_token>
Content-Type: application/json

{
  "beneficiaryName": "Jane Smith",
  "beneficiaryAccountNumber": "987654321",
  "swiftBic": "CHASUS33XXX",
  "iban": "US12345678901234567890",        // optional
  "beneficiaryAddress": "123 Main St",
  "beneficiaryCity": "New York",
  "beneficiaryPostalCode": "10001",
  "beneficiaryCountry": "US"
}

Response 200:
{
  "success": true,
  "message": "Beneficiary details updated",
  "data": {
    "id": "cm...",
    "amount": 1000.00,
    "beneficiaryName": "Jane Smith",
    "swiftBic": "CHASUS33XXX",
    ...
  }
}
```

#### **Submit Payment for Verification**
```http
POST /api/v1/payments/{id}/submit
Authorization: Bearer <access_token>
Content-Type: application/json

{
  "reference": "PAY-2025-001",  // optional, updates if provided
  "purpose": "Final purpose"     // optional, updates if provided
}

Response 200:
{
  "success": true,
  "message": "Payment submitted for verification",
  "data": {
    "id": "cm...",
    "status": "pending_verification",
    ...
  }
}
```

#### **Get User's Payments**
```http
GET /api/v1/payments?page=1&limit=20&status=completed&sortBy=createdAt&sortOrder=desc
Authorization: Bearer <access_token>

Response 200:
{
  "success": true,
  "data": {
    "payments": [...],
    "pagination": {
      "page": 1,
      "limit": 20,
      "total": 45,
      "totalPages": 3
    }
  }
}
```

#### **Get Payment Details**
```http
GET /api/v1/payments/{id}
Authorization: Bearer <access_token>

Response 200:
{
  "success": true,
  "data": {
    "id": "cm...",
    "amount": 1000.00,
    "currency": "USD",
    "status": "completed",
    "beneficiaryName": "Jane Smith",
    "swiftBic": "CHASUS33XXX",
    "createdAt": "2025-01-10T...",
    "completedAt": "2025-01-10T...",
    ...
  }
}
```

#### **Delete Draft Payment**
```http
DELETE /api/v1/payments/{id}
Authorization: Bearer <access_token>

Response 200:
{
  "success": true,
  "message": "Draft payment deleted"
}
```

### **Staff Payment Endpoints**

#### **Get Pending Verification Queue**
```http
GET /api/v1/payments/staff/queue?page=1&limit=20
Authorization: Bearer <staff_token>

Response 200:
{
  "success": true,
  "data": {
    "payments": [
      {
        "id": "cm...",
        "amount": 1000.00,
        "currency": "USD",
        "status": "pending_verification",
        "customerName": "John Doe",
        "customerEmail": "john@example.com",
        "submittedAt": "2025-01-10T...",
        ...
      }
    ],
    "pagination": {...}
  }
}
```

#### **Get Verified Payments (Ready for SWIFT)**
```http
GET /api/v1/payments/staff/verified?page=1&limit=20
Authorization: Bearer <staff_token>

Response 200:
{
  "success": true,
  "data": {
    "payments": [...],
    "pagination": {...}
  }
}
```

#### **Get SWIFT Submitted Payments**
```http
GET /api/v1/payments/staff/swift?page=1&limit=20
Authorization: Bearer <staff_token>

Response 200:
{
  "success": true,
  "data": {
    "payments": [...],
    "pagination": {...}
  }
}
```

#### **Verify or Reject Payment**
```http
POST /api/v1/payments/{id}/verify
Authorization: Bearer <staff_token>
Content-Type: application/json

{
  "action": "approve"  // or "reject"
}

Response 200 (Approved):
{
  "success": true,
  "message": "Payment verified successfully",
  "data": {
    "id": "cm...",
    "status": "verified",
    "staffVerifiedAt": "2025-01-10T...",
    ...
  }
}

Response 200 (Rejected):
{
  "success": true,
  "message": "Payment rejected",
  "data": {
    "id": "cm...",
    "status": "rejected",
    ...
  }
}
```

#### **Submit Payment to SWIFT**
```http
POST /api/v1/payments/{id}/submit-swift
Authorization: Bearer <staff_token>

Response 200:
{
  "success": true,
  "message": "Payment submitted to SWIFT network",
  "data": {
    "id": "cm...",
    "status": "submitted_to_swift",
    "submittedToSwiftAt": "2025-01-10T...",
    "swiftReference": "SWT20250110ABCD1234",
    ...
  }
}
```

### **Beneficiary Endpoints**

#### **List Beneficiaries**
```http
GET /api/v1/beneficiaries
Authorization: Bearer <access_token>

Response 200:
{
  "success": true,
  "data": [
    {
      "id": "cm...",
      "beneficiaryName": "Jane Smith",
      "swiftBic": "CHASUS33XXX",
      "accountNumber": "***4567",  // masked
      "bankName": "Chase Bank",
      "country": "US",
      "createdAt": "2025-01-10T..."
    }
  ]
}
```

#### **Create Beneficiary**
```http
POST /api/v1/beneficiaries
Authorization: Bearer <access_token>
Content-Type: application/json

{
  "beneficiaryName": "Jane Smith",
  "swiftBic": "CHASUS33XXX",
  "accountNumber": "987654321",
  "iban": "US12345678901234567890",
  "bankName": "Chase Bank",
  "address": "123 Main St",
  "city": "New York",
  "postalCode": "10001",
  "country": "US"
}

Response 201:
{
  "success": true,
  "message": "Beneficiary created successfully",
  "data": {
    "id": "cm...",
    ...
  }
}
```

#### **Delete Beneficiary**
```http
DELETE /api/v1/beneficiaries/{id}
Authorization: Bearer <access_token>

Response 200:
{
  "success": true,
  "message": "Beneficiary deleted successfully"
}
```

---

## 🔒 Security Implementation

### **Password Security**
- **Argon2id** hashing algorithm (OWASP recommended)
- **Memory cost**: 64 MB (65536 KiB)
- **Time cost**: 3 iterations
- **Parallelism**: 1 thread
- **Salt**: Automatically generated per password
- **No plaintext storage**: Passwords never stored or logged

### **Data Encryption**
- **Algorithm**: AES-256-GCM (AEAD)
- **Key derivation**: PBKDF2 with SHA-256
- **Envelope encryption**: Master key → DEK → Data
- **Authenticated encryption**: Prevents tampering
- **IV/Nonce**: Unique per encryption operation
- **Encrypted fields**:
  - Email addresses
  - South African ID numbers
  - Beneficiary account numbers
  - Beneficiary addresses
  - Any PII data

### **JWT Security**
- **Algorithm**: HS256 (HMAC-SHA256)
- **Access token**: 15 minutes expiry
- **Refresh token**: 7 days expiry
- **Claims**: iss, sub, role, iat, exp
- **Storage**: Client-side in httpOnly cookies (recommended) or localStorage
- **Validation**: Signature, expiry, and issuer verification

### **Attack Prevention**
- **SQL Injection**: Prisma ORM with parameterized queries
- **XSS**: Input sanitization and output encoding
- **CSRF**: Token-based verification
- **DoS**: Rate limiting per IP and endpoint
- **Brute Force**: Account lockout after failed attempts
- **Session Fixation**: Token rotation on privilege change
- **Path Traversal**: Input validation and sanitization

---

## 📊 Database Schema

### **Core Models**

#### **User**
```prisma
model User {
  id                String    @id @default(cuid())
  fullName          String
  saIdEncrypted     String?   // Encrypted South African ID
  emailEncrypted    String?   // Encrypted email
  accountNumber     String    @unique
  passwordHash      String
  role              String    @default("customer")
  failedLoginAttempts Int     @default(0)
  lockedUntil       DateTime?
  createdAt         DateTime  @default(now())
  updatedAt         DateTime  @updatedAt
  
  payments          Payment[]
  beneficiaries     Beneficiary[]
  refreshTokens     RefreshToken[]
}
```

#### **Payment**
```prisma
model Payment {
  id                    String    @id @default(cuid())
  userId                String
  amount                Float
  currency              String
  provider              String
  status                String    @default("draft")
  reference             String?
  purpose               String?
  beneficiaryNameEnc    String?   // Encrypted
  beneficiaryAccountEnc String?   // Encrypted
  swiftBic              String?
  iban                  String?
  beneficiaryAddressEnc String?   // Encrypted
  idempotencyKey        String?   @unique
  
  createdAt             DateTime  @default(now())
  updatedAt             DateTime  @updatedAt
  submittedAt           DateTime?
  staffVerifiedAt       DateTime?
  submittedToSwiftAt    DateTime?
  completedAt           DateTime?
  
  user                  User      @relation(fields: [userId], references: [id])
}
```

#### **Beneficiary**
```prisma
model Beneficiary {
  id              String    @id @default(cuid())
  userId          String
  beneficiaryName String
  swiftBic        String
  accountNumberEnc String   // Encrypted
  iban            String?
  bankName        String?
  addressEnc      String?   // Encrypted
  city            String?
  postalCode      String?
  country         String
  createdAt       DateTime  @default(now())
  updatedAt       DateTime  @updatedAt
  
  user            User      @relation(fields: [userId], references: [id])
}
```

#### **OtpCode**
```prisma
model OtpCode {
  id        String    @id @default(cuid())
  userId    String?
  email     String
  code      String
  purpose   String    @default("login")
  expiresAt DateTime
  verified  Boolean   @default(false)
  createdAt DateTime  @default(now())
}
```

---

## 🧪 Testing

### **Test Database**
```bash
# Reset and seed test database
npm run db:reset
npm run db:seed
```

### **Test Users** (from seed)
```
Customer:
- Email: customer@nexuspay.dev
- Account: 12345678
- Password: Customer123!

Staff:
- Email: staff@nexuspay.dev
- Account: 87654321
- Password: Staff123!

Admin:
- Email: admin@nexuspay.dev
- Account: 11111111
- Password: Admin123!
```

### **Manual API Testing**
```bash
# Health check
curl http://localhost:5118/health

# Register (will return 400 if user exists)
curl -X POST http://localhost:5118/api/v1/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "fullName": "Test User",
    "saId": "9001015009087",
    "accountNumber": "99999999",
    "email": "test@example.com",
    "password": "Test123!"
  }'

# Login (customer - triggers OTP)
curl -X POST http://localhost:5118/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "usernameOrEmail": "customer@nexuspay.dev",
    "accountNumber": "12345678",
    "password": "Customer123!"
  }'

# Check console for OTP, then login with OTP
curl -X POST http://localhost:5118/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "usernameOrEmail": "customer@nexuspay.dev",
    "accountNumber": "12345678",
    "password": "Customer123!",
    "otp": "123456"
  }'
```

---

## 🚀 Deployment

### **Production Checklist**

#### **Environment**
- [ ] Set `NODE_ENV=production`
- [ ] Use strong, unique secrets for JWT and CSRF
- [ ] Configure production database (PostgreSQL/MySQL)
- [ ] Set up KMS/HSM for encryption keys
- [ ] Configure real SMTP server
- [ ] Set allowed origins for CORS

#### **Database**
- [ ] Run migrations: `npx prisma migrate deploy`
- [ ] Enable encryption at rest
- [ ] Set up automated backups
- [ ] Configure connection pooling
- [ ] Enable query logging for audit

#### **Security**
- [ ] Configure TLS 1.3 certificates
- [ ] Set up WAF rules
- [ ] Enable rate limiting
- [ ] Configure security headers
- [ ] Set up SIEM integration
- [ ] Enable audit logging

#### **SWIFT Integration**
- [ ] Configure mTLS certificates
- [ ] Set SWIFT API credentials
- [ ] Test SWIFT connectivity
- [ ] Set up MT103 message generation
- [ ] Configure callback endpoints

#### **Monitoring**
- [ ] Set up application monitoring (New Relic, Datadog, etc.)
- [ ] Configure error tracking (Sentry)
- [ ] Set up log aggregation (ELK, Splunk)
- [ ] Configure alerts and notifications
- [ ] Set up uptime monitoring

### **Docker Deployment**

```dockerfile
# Dockerfile
FROM node:18-alpine

WORKDIR /app

# Install dependencies
COPY package*.json ./
RUN npm ci --only=production

# Copy source
COPY . .

# Generate Prisma client
RUN npx prisma generate

# Build TypeScript
RUN npm run build

# Expose port
EXPOSE 5118

# Start server
CMD ["npm", "start"]
```

```bash
# Build image
docker build -t nexuspay-api:latest .

# Run container
docker run -d \
  -p 5118:5118 \
  --env-file .env \
  --name nexuspay-api \
  nexuspay-api:latest
```

### **Cloud Deployment**

#### **AWS**
- Deploy on ECS Fargate or EC2
- Use RDS for PostgreSQL
- Store secrets in Secrets Manager
- Use CloudWatch for logging
- Configure ALB with TLS termination

#### **Azure**
- Deploy on App Service or AKS
- Use Azure Database for PostgreSQL
- Store secrets in Key Vault
- Use Application Insights
- Configure Application Gateway

#### **Google Cloud**
- Deploy on Cloud Run or GKE
- Use Cloud SQL for PostgreSQL
- Store secrets in Secret Manager
- Use Cloud Logging
- Configure Cloud Load Balancer

---

## 📚 Additional Resources

- **SMTP Setup Guide**: `./SMTP_SETUP.md`
- **Compliance Analysis**: `../TASK_2_COMPLIANCE_ANALYSIS.md`
- **Requirements Gap**: `../REQUIREMENTS_GAP_ANALYSIS.md`
- **Frontend README**: `../nexuspay/README.md`

---

## 🤝 Contributing

We welcome contributions! Please follow these guidelines:

1. **Fork the repository**
2. **Create a feature branch** (`git checkout -b feature/amazing-feature`)
3. **Follow TypeScript strict mode**
4. **Write comprehensive tests**
5. **Update documentation**
6. **Commit with clear messages**
7. **Open a Pull Request**

---

## 📄 License

This project is proprietary software developed for NexusPay. All rights reserved.

---

## 🆘 Support

For support:
- **Documentation**: Check this README and related docs
- **Issues**: Create a GitHub issue
- **Email**: backend-team@nexuspay.com
- **Slack**: #nexuspay-backend (internal)

---

## 🔄 Changelog

### **v1.3.0** (Latest)
- ✅ Email-based OTP authentication for customers
- ✅ Staff OTP bypass for streamlined access
- ✅ SMTP integration with multiple provider support
- ✅ Development mode OTP console logging
- ✅ Automatic OTP cleanup service
- ✅ Enhanced security event logging

### **v1.2.0**
- ✅ Beneficiary CRUD endpoints
- ✅ Staff verification queues (pending, verified, SWIFT)
- ✅ Payment reference and purpose fields
- ✅ Customer visibility for staff
- ✅ SWIFT/BIC and IBAN validation
- ✅ Enhanced error handling

### **v1.1.0**
- ✅ Fixed AES-GCM nonce usage in DEK decryption
- ✅ Resolved JWT issuer conflict
- ✅ Added staff endpoints
- ✅ Implemented comprehensive logging
- ✅ Added rate limiting

### **v1.0.0**
- ✅ Initial release
- ✅ Task 2 compliance implementation
- ✅ JWT authentication
- ✅ Payment workflow
- ✅ Field-level encryption
- ✅ Immutable audit logging

---

**NexusPay API** - Enterprise-grade security for international payments. 🔒🚀
