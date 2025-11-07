# Security Testing Suite

This directory contains comprehensive security tests for the NexusPay API, implementing endpoint-level attack simulation and security validation.

## Overview

The security testing suite covers:

- **Brute Force Protection**: Login/registration rate limiting and account lockout
- **Injection Attacks**: SQL, XSS, NoSQL, command injection, path traversal
- **Rate Limiting**: API, login, registration, and WAF rate limits
- **Authentication Security**: Token validation, RBAC, bypass prevention
- **CORS Security**: Preflight handling, origin whitelisting, header exposure
- **Error Leakage Prevention**: Ensures sensitive information is not exposed
- **Malformed Payload Handling**: Invalid JSON, type confusion, prototype pollution

## Running Tests

### Run All Security Tests

```bash
npm run test:security
```

### Run Specific Test Suite

```bash
# Brute force tests
npm test -- tests/security/bruteForce.test.ts

# Injection attack tests
npm test -- tests/security/injectionAttacks.test.ts

# Rate limiting tests
npm test -- tests/security/rateLimiting.test.ts

# Authentication tests
npm test -- tests/security/authentication.test.ts

# CORS tests
npm test -- tests/security/cors.test.ts

# Error leakage tests
npm test -- tests/security/errorLeakage.test.ts

# Malformed payload tests
npm test -- tests/security/malformedPayloads.test.ts
```

### Watch Mode

```bash
npm run test:security:watch
```

### With Coverage

```bash
npm run test:coverage
```

## Test Structure

### Test Helpers

- `tests/helpers/testServer.ts`: Server setup and supertest integration
- `tests/helpers/attackPayloads.ts`: Collection of attack payloads for testing

### Test Suites

1. **bruteForce.test.ts**: Tests brute force protection mechanisms
   - Login rate limiting
   - Registration rate limiting
   - Account lockout functionality

2. **injectionAttacks.test.ts**: Tests injection attack prevention
   - SQL injection
   - XSS attacks
   - NoSQL injection
   - Command injection
   - Path traversal
   - WAF blocking

3. **rateLimiting.test.ts**: Tests rate limiting across endpoints
   - General API rate limiting
   - Login endpoint rate limiting
   - Registration endpoint rate limiting
   - WAF rate limiting

4. **authentication.test.ts**: Tests authentication security
   - Token validation
   - Role-based access control (RBAC)
   - Session management
   - Authentication bypass prevention

5. **cors.test.ts**: Tests CORS security
   - Preflight requests
   - Origin whitelisting
   - Header exposure
   - Credentials handling

6. **errorLeakage.test.ts**: Tests error message security
   - Database error handling
   - System information leakage
   - Authentication error messages
   - Input validation errors

7. **malformedPayloads.test.ts**: Tests malformed payload handling
   - Invalid JSON
   - Type confusion
   - Prototype pollution
   - Oversized payloads
   - Content-Type validation

## Attack Payloads

The `attackPayloads.ts` file contains comprehensive collections of attack payloads:

- **SQL Injection**: 25+ SQL injection payloads
- **XSS**: 20+ XSS attack vectors
- **NoSQL Injection**: 20+ NoSQL injection patterns
- **Command Injection**: 25+ command injection attempts
- **Path Traversal**: 15+ path traversal patterns
- **LDAP Injection**: 15+ LDAP injection attempts
- **XXE**: XML external entity injection payloads
- **Template Injection**: Server-side template injection
- **Prototype Pollution**: JavaScript prototype pollution attempts

## CI/CD Integration

Security tests run automatically in CI/CD:

- **On every push/PR**: Runs security test suite
- **Nightly at 2 AM UTC**: Full security scan including OWASP ZAP
- **Manual trigger**: Via GitHub Actions workflow_dispatch

## OWASP ZAP Integration

For comprehensive vulnerability scanning, use OWASP ZAP:

### Start ZAP

```bash
# Using Docker
docker run -d -p 8080:8080 owasp/zap2docker-stable zap.sh -daemon -host 0.0.0.0 -port 8080 -config api.disablekey=true
```

### Run ZAP Scan

**Windows:**
```powershell
npm run zap:scan
```

**Linux/Mac:**
```bash
npm run zap:scan:linux
```

### ZAP Scan Results

Reports are saved to `reports/zap/`:
- HTML report: `zap-report-YYYYMMDD-HHMMSS.html`
- JSON report: `zap-report-YYYYMMDD-HHMMSS.json`

## Test Environment Setup

1. **Database**: Tests use a separate test database
2. **Environment Variables**: Set `NODE_ENV=test`
3. **Server**: Tests use a test server instance (not the production server)

## Best Practices

1. **Isolation**: Each test should be independent
2. **Cleanup**: Tests should clean up after themselves
3. **Realistic Payloads**: Use real-world attack payloads
4. **Coverage**: Aim for comprehensive coverage of security features
5. **Documentation**: Document any test-specific requirements

## Troubleshooting

### Tests Failing

1. Check database connection
2. Verify environment variables
3. Ensure test database is set up
4. Check server is not already running on test port

### Rate Limiting Tests

Rate limiting tests may be sensitive to timing. If tests fail:
- Increase test timeout
- Check rate limit configuration
- Verify rate limit store (memory vs Redis)

### ZAP Connection Issues

If ZAP scan fails:
1. Verify ZAP is running: `curl http://localhost:8080/JSON/core/view/version/`
2. Check ZAP port configuration
3. Ensure API server is running before scan

## Contributing

When adding new security tests:

1. Follow existing test structure
2. Use attack payloads from `attackPayloads.ts`
3. Document test purpose and expected behavior
4. Ensure tests are deterministic
5. Add to appropriate test suite or create new one

## References

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [OWASP ZAP](https://www.zaproxy.org/)
- [Jest Documentation](https://jestjs.io/)
- [Supertest Documentation](https://github.com/visionmedia/supertest)

