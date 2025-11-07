import { getTestRequest } from '../helpers/testServer';
import {
  SQL_INJECTION_PAYLOADS,
  XSS_PAYLOADS,
  NOSQL_INJECTION_PAYLOADS,
  COMMAND_INJECTION_PAYLOADS,
  PATH_TRAVERSAL_PAYLOADS,
} from '../helpers/attackPayloads';

describe('Injection Attack Prevention', () => {
  const request = getTestRequest();

  describe('SQL Injection Prevention', () => {
    it('should block SQL injection in login username', async () => {
      for (const payload of SQL_INJECTION_PAYLOADS.slice(0, 5)) {
        const response = await request
          .post('/api/v1/auth/login')
          .send({
            usernameOrEmail: payload,
            accountNumber: '12345678',
            password: 'Test123!',
          });

        // Should either block (403) or reject (400/401), not execute SQL
        expect([400, 401, 403]).toContain(response.status);
        expect(response.body.code).not.toBeUndefined();
      }
    });

    it('should block SQL injection in registration fields', async () => {
      for (const payload of SQL_INJECTION_PAYLOADS.slice(0, 3)) {
        const response = await request
          .post('/api/v1/auth/register')
          .send({
            fullName: payload,
            saId: '1234567890123',
            accountNumber: '12345678',
            email: 'test@example.com',
            password: 'Test123!',
          });

        // Should reject invalid input
        expect([400, 403]).toContain(response.status);
      }
    });
  });

  describe('XSS Prevention', () => {
    it('should sanitize XSS payloads in input fields', async () => {
      for (const payload of XSS_PAYLOADS.slice(0, 5)) {
        const response = await request
          .post('/api/v1/auth/register')
          .send({
            fullName: payload,
            saId: '1234567890123',
            accountNumber: '12345678',
            email: 'test@example.com',
            password: 'Test123!',
          });

        // Should either reject or sanitize
        expect([400, 403]).toContain(response.status);
        
        // If it returns success, verify the payload is sanitized
        if (response.status === 201) {
          expect(response.body.data?.fullName).not.toContain('<script>');
          expect(response.body.data?.fullName).not.toContain('javascript:');
        }
      }
    });

    it('should block XSS in URL parameters', async () => {
      for (const payload of XSS_PAYLOADS.slice(0, 3)) {
        const encodedPayload = encodeURIComponent(payload);
        const response = await request
          .get(`/api/v1/auth/me?param=${encodedPayload}`);

        // Should block or sanitize
        expect([400, 401, 403]).toContain(response.status);
      }
    });
  });

  describe('NoSQL Injection Prevention', () => {
    it('should block NoSQL injection in request body', async () => {
      for (const payload of NOSQL_INJECTION_PAYLOADS.slice(0, 5)) {
        const response = await request
          .post('/api/v1/auth/login')
          .send({
            usernameOrEmail: payload as any,
            accountNumber: '12345678',
            password: 'Test123!',
          });

        // Should reject malformed input
        expect([400, 403]).toContain(response.status);
      }
    });

    it('should block NoSQL injection in query parameters', async () => {
      const payload = { $ne: null };
      const response = await request
        .get('/api/v1/auth/me')
        .query(payload);

      // Should reject or ignore malicious query
      expect([400, 401, 403]).toContain(response.status);
    });
  });

  describe('Command Injection Prevention', () => {
    it('should block command injection in input fields', async () => {
      for (const payload of COMMAND_INJECTION_PAYLOADS.slice(0, 5)) {
        const response = await request
          .post('/api/v1/auth/register')
          .send({
            fullName: payload,
            saId: '1234567890123',
            accountNumber: '12345678',
            email: 'test@example.com',
            password: 'Test123!',
          });

        // Should block command injection attempts
        expect([400, 403]).toContain(response.status);
      }
    });
  });

  describe('Path Traversal Prevention', () => {
    it('should block path traversal in file operations', async () => {
      for (const payload of PATH_TRAVERSAL_PAYLOADS.slice(0, 5)) {
        const response = await request
          .get(`/api/v1/files/${encodeURIComponent(payload)}`);

        // Should block path traversal
        expect([400, 403, 404]).toContain(response.status);
      }
    });

  });

  describe('WAF Blocking', () => {
    it('should return WAF_BLOCKED code for blocked requests', async () => {
      const response = await request
        .post('/api/v1/auth/login')
        .send({
          usernameOrEmail: "' OR '1'='1",
          accountNumber: '12345678',
          password: 'Test123!',
        });

      if (response.status === 403) {
        expect(response.body.code).toBe('WAF_BLOCKED');
      }
    });
  });
});

