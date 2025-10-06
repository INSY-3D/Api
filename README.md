# NexusPay API - Task 2 Compliant

A secure, enterprise-grade Node.js API for international payments with full Task 2 compliance.

## 🚀 Features

### Task 2 Compliance
- ✅ **TLS 1.3 Only** - All traffic encrypted with TLS 1.3
- ✅ **Argon2id Password Hashing** - Industry-standard password security
- ✅ **PII Encryption** - Envelope encryption for sensitive data
- ✅ **Input Validation** - Server-side RegEx allowlist validation
- ✅ **Attack Protections** - WAF, rate limiting, security headers
- ✅ **Immutable Audit Logging** - Tamper-evident audit trails
- ✅ **Multi-step Payment Workflow** - Draft → Beneficiary → Submit
- ✅ **SWIFT Integration** - Ready for mTLS SWIFT connectivity

### Security Features
- 🔐 JWT authentication with refresh tokens
- 🛡️ Web Application Firewall (WAF)
- 🚦 Rate limiting and DDoS protection
- 🔒 CSRF protection
- 📊 Security event logging
- 🔍 Input sanitization and validation
- 🚨 SIEM integration ready

### Architecture
- 🏗️ TypeScript with strict type checking
- 🗄️ Prisma ORM with SQLite (dev) and Postgres/MySQL ready (prod)
- 📝 Comprehensive logging with Winston
- 🔄 Graceful error handling
- 📈 Performance monitoring
- 🧪 Unit and integration tests

## 📋 Prerequisites

- Node.js 18+
- npm 8+
- SQLite (dev) or a PostgreSQL/MySQL instance (prod)

## 🛠️ Installation

1. **Clone the repository**
   ```bash
   git clone <repository-url>
   cd nexuspay-api
   ```

2. **Install dependencies**
   ```bash
   npm install
   ```

3. **Environment setup**
   ```bash
   cp env.example .env
   # Edit .env with your configuration
   ```

4. **Database setup**
   ```bash
   # Generate Prisma client
   npm run db:generate
   
  # Create/Reset dev DB and apply schema (SQLite)
  npm run db:reset
   
   # Seed the database (optional)
   npm run db:seed
   ```

5. **Start the server**
   ```bash
   # Development
   npm run dev
   
   # Production
   npm run build
   npm start
   ```

## 🔧 Configuration

### Environment Variables

Key configuration options in `.env`:

```env
# Server
NODE_ENV=development
PORT=5118
HOST=localhost

# Database (SQLite for development)
DATABASE_URL="file:./nexuspay.db"

# JWT
JWT_SECRET="your-super-secure-jwt-secret-key-here-minimum-32-characters"
JWT_REFRESH_SECRET="your-super-secure-refresh-secret-key-here-minimum-32-characters"

# Encryption
ENCRYPTION_MASTER_KEY_ID="nexuspay-master-key-2025"

# Argon2id
ARGON2_MEMORY_COST=65536
ARGON2_TIME_COST=3
ARGON2_PARALLELISM=1

# SWIFT
SWIFT_BASE_URL="https://swift-gateway.nexuspay.bank"
SWIFT_SENDER_BIC="NEXUSZAJJ"
```

## 📚 API Documentation

### Authentication Endpoints

#### Register User
```http
POST /api/v1/auth/register
Content-Type: application/json

{
  "fullName": "John Doe",
  "saId": "1234567890123",
  "accountNumber": "12345678",
  "email": "john@example.com",
  "password": "SecurePass123!"
}
```

#### Login
```http
POST /api/v1/auth/login
Content-Type: application/json

{
  "usernameOrEmail": "john@example.com",
  "accountNumber": "12345678",
  "password": "SecurePass123!"
}
```

#### Staff Login
```http
POST /api/v1/auth/staff-login
Content-Type: application/json

{
  "usernameOrEmail": "staff@nexuspay.dev",
  "accountNumber": "87654321",
  "password": "StaffPass123!"
}
```

### Payment Endpoints

#### Create Draft Payment
```http
POST /api/v1/payments
Authorization: Bearer <token>
Content-Type: application/json

{
  "amount": "1000.00",
  "currency": "USD",
  "provider": "SWIFT",
  "reference": "Optional reference up to 35 chars",
  "purpose": "Optional purpose up to 140 chars",
  "idempotencyKey": "unique-key-123"
}
```

#### Update Beneficiary
```http
PUT /api/v1/payments/{id}/beneficiary
Authorization: Bearer <token>
Content-Type: application/json

{
  "beneficiaryName": "Jane Smith",
  "beneficiaryAccountNumber": "987654321",
  "swiftBic": "CHASUS33XXX",
  "beneficiaryAddress": "123 Main St",
  "beneficiaryCity": "New York",
  "beneficiaryPostalCode": "10001",
  "beneficiaryCountry": "US"
}
```

#### Submit Payment
```http
POST /api/v1/payments/{id}/submit
Authorization: Bearer <token>
Content-Type: application/json

{
  "reference": "PAY-2025-001"?,
  "purpose": "Business payment"?
}
```

#### Staff Queue (Pending Verification)
```http
GET /api/v1/payments/staff/queue?page=1&limit=20
Authorization: Bearer <token>
```

#### Staff Verified (Ready for SWIFT)
```http
GET /api/v1/payments/staff/verified?page=1&limit=20
Authorization: Bearer <token>
```

#### Staff Submitted to SWIFT
```http
GET /api/v1/payments/staff/swift?page=1&limit=20
Authorization: Bearer <token>
```

#### Verify/Reject a Payment
```http
POST /api/v1/payments/{id}/verify
Authorization: Bearer <token>
Content-Type: application/json

{ "action": "approve" | "reject" }
```

#### Submit a Payment to SWIFT
```http
POST /api/v1/payments/{id}/submit-swift
Authorization: Bearer <token>
```

### Beneficiaries Endpoints (CRUD)

#### List
```http
GET /api/v1/beneficiaries
Authorization: Bearer <token>
```

#### Create
```http
POST /api/v1/beneficiaries
Authorization: Bearer <token>
Content-Type: application/json
```

#### Delete
```http
DELETE /api/v1/beneficiaries/{id}
Authorization: Bearer <token>
```

## 🔒 Security Features

### WAF Protection
- SQL injection detection
- XSS attack prevention
- Path traversal protection
- Command injection blocking
- LDAP injection prevention

### Rate Limiting
- General API: 100 requests/15 minutes
- Login: 5 attempts/15 minutes
- Registration: 3 attempts/hour
- WAF: 1000 requests/minute

### Security Headers
- Content Security Policy (CSP)
- HTTP Strict Transport Security (HSTS)
- X-Frame-Options: DENY
- X-Content-Type-Options: nosniff
- Referrer-Policy: strict-origin-when-cross-origin

## 🧪 Testing

```bash
# Run all tests
npm test

# Run tests in watch mode
npm run test:watch

# Run tests with coverage
npm run test:coverage
```

## 📊 Monitoring

### Health Check
```http
GET /health
```

### Logs
- Application logs: `logs/combined.log`
- Error logs: `logs/error.log`
- Security logs: `logs/security.log`
- Audit logs: `logs/audit.log`
- Performance logs: `logs/performance.log`

## 🚀 Deployment

### Production Checklist
- [ ] Update environment variables
- [ ] Configure TLS certificates
- [ ] Set up PostgreSQL with encryption
- [ ] Configure KMS/HSM for encryption keys
- [ ] Set up monitoring and alerting
- [ ] Configure backup strategy
- [ ] Test security configurations

### Docker Support
```bash
# Build image
docker build -t nexuspay-api .

# Run container
docker run -p 5118:5118 --env-file .env nexuspay-api
```

## 📝 Development

### Project Structure
```
src/
├── config/          # Configuration files
├── controllers/     # Request handlers
├── middleware/      # Express middleware
├── routes/          # API routes
├── services/        # Business logic
├── types/           # TypeScript types
├── utils/           # Utility functions
└── validators/      # Input validation
```

### Code Style
- ESLint for linting
- Prettier for formatting
- TypeScript strict mode
- Comprehensive error handling

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests
5. Submit a pull request

## 📄 License

This project is licensed under the MIT License.

## 🆘 Support

For support and questions:
- Create an issue in the repository
- Contact the development team
- Check the documentation

## 🔄 Changelog

### v1.0.0
- Initial release
- Task 2 compliance implementation
- Full payment workflow
- Security features
- SWIFT integration ready

### v1.1.0
- Fixed AES-GCM nonce usage in DEK decryption
- Resolved JWT issuer conflict (payload `iss` only; no `issuer` option)
- Added staff endpoints: queue, verified, submitted to SWIFT, verify action
- Implemented Beneficiaries CRUD endpoints
- Aligned SWIFT/BIC and IBAN validation with frontend
- Added `reference` and `purpose` support on drafts and submission
- Included `customerName`/`customerEmail` in payment DTOs for staff views
