import { getTestRequest } from '../helpers/testServer';
import { PROTOTYPE_POLLUTION_PAYLOADS } from '../helpers/attackPayloads';

describe('Malformed Payload Handling', () => {
  const request = getTestRequest();

  describe('Invalid JSON Handling', () => {
    it('should reject malformed JSON', async () => {
      const response = await request
        .post('/api/v1/auth/login')
        .set('Content-Type', 'application/json')
        .send('{ invalid json }');

      expect([400, 500]).toContain(response.status);
    });

    it('should reject incomplete JSON', async () => {
      const response = await request
        .post('/api/v1/auth/login')
        .set('Content-Type', 'application/json')
        .send('{"usernameOrEmail":');

      expect([400, 500]).toContain(response.status);
    });

    it('should reject JSON with invalid encoding', async () => {
      const response = await request
        .post('/api/v1/auth/login')
        .set('Content-Type', 'application/json; charset=utf-8')
        .send(Buffer.from([0xFF, 0xFE, 0xFD]));

      expect([400, 500]).toContain(response.status);
    });
  });

  describe('Type Confusion Attacks', () => {
    it('should handle type coercion attempts', async () => {
      const response = await request
        .post('/api/v1/auth/login')
        .send({
          usernameOrEmail: 12345,
          accountNumber: true,
          password: [],
        });

      // Should reject type mismatches
      expect([400, 422]).toContain(response.status);
    });

    it('should handle null/undefined injection', async () => {
      const response = await request
        .post('/api/v1/auth/login')
        .send({
          usernameOrEmail: null,
          accountNumber: undefined,
          password: null,
        });

      // Should reject null/undefined in required fields
      expect([400, 422]).toContain(response.status);
    });

    it('should handle array instead of string', async () => {
      const response = await request
        .post('/api/v1/auth/login')
        .send({
          usernameOrEmail: ['admin', 'user'],
          accountNumber: '12345678',
          password: 'Test123!',
        });

      // Should reject type mismatches
      expect([400, 422]).toContain(response.status);
    });

    it('should handle object instead of string', async () => {
      const response = await request
        .post('/api/v1/auth/login')
        .send({
          usernameOrEmail: { user: 'admin' },
          accountNumber: '12345678',
          password: 'Test123!',
        });

      // Should reject type mismatches
      expect([400, 422]).toContain(response.status);
    });
  });

  describe('Prototype Pollution Prevention', () => {
    it('should prevent prototype pollution in request body', async () => {
      for (const payload of PROTOTYPE_POLLUTION_PAYLOADS) {
        const response = await request
          .post('/api/v1/auth/register')
          .send({
            ...payload,
            fullName: 'Test User',
            saId: '1234567890123',
            accountNumber: '12345678',
            email: 'test@example.com',
            password: 'Test123!',
          });

        // Should reject or sanitize prototype pollution attempts
        expect([400, 403]).toContain(response.status);
      }
    });

    it('should prevent constructor pollution', async () => {
      const response = await request
        .post('/api/v1/auth/register')
        .send({
          constructor: { prototype: { isAdmin: true } },
          fullName: 'Test User',
          saId: '1234567890123',
          accountNumber: '12345678',
          email: 'test@example.com',
          password: 'Test123!',
        });

      // Should reject constructor pollution
      expect([400, 403]).toContain(response.status);
    });
  });

  describe('Oversized Payloads', () => {
    it('should reject payloads with excessive nesting', async () => {
      let deeplyNested: any = {};
      let current = deeplyNested;
      for (let i = 0; i < 100; i++) {
        current[i] = {};
        current = current[i];
      }

      const response = await request
        .post('/api/v1/auth/register')
        .send({
          data: deeplyNested,
          fullName: 'Test User',
          saId: '1234567890123',
          accountNumber: '12345678',
          email: 'test@example.com',
          password: 'Test123!',
        });

      // Should reject or limit nesting depth
      expect([400, 413]).toContain(response.status);
    });
  });

  describe('Content-Type Validation', () => {
    it('should reject requests with wrong Content-Type', async () => {
      const response = await request
        .post('/api/v1/auth/login')
        .set('Content-Type', 'text/plain')
        .send('username=test&password=test');

      // Should reject or handle appropriately
      expect([400, 415]).toContain(response.status);
    });

  });

  describe('Special Character Handling', () => {
    it('should handle unicode injection attempts', async () => {
      const response = await request
        .post('/api/v1/auth/register')
        .send({
          fullName: '\u0000\u0001\u0002\u0003',
          saId: '1234567890123',
          accountNumber: '12345678',
          email: 'test@example.com',
          password: 'Test123!',
        });

      // Should sanitize or reject control characters
      expect([200, 400, 403]).toContain(response.status);
    });

    it('should handle emoji and special unicode', async () => {
      const response = await request
        .post('/api/v1/auth/register')
        .send({
          fullName: 'Test 👤 User 🎉',
          saId: '1234567890123',
          accountNumber: '12345678',
          email: 'test@example.com',
          password: 'Test123!',
        });

      // Should handle unicode appropriately
      expect([200, 201, 400]).toContain(response.status);
    });
  });
});
