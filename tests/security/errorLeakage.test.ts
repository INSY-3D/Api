import { getTestRequest } from '../helpers/testServer';

describe('Error Leakage Prevention', () => {
  const request = getTestRequest();

  describe('Database Error Handling', () => {
    it('should not expose database errors to clients', async () => {
      // Try to trigger a database error with invalid input
      const response = await request
        .post('/api/v1/auth/register')
        .send({
          fullName: 'Test',
          saId: 'invalid',
          accountNumber: '12345678',
          email: 'test@example.com',
          password: 'Test123!',
        });

      // Error response should not contain database-specific information
      if (response.status >= 400) {
        expect(response.body.message).not.toContain('SQL');
        expect(response.body.message).not.toContain('database');
        expect(response.body.message).not.toContain('Prisma');
        expect(response.body.message).not.toContain('constraint');
        expect(response.body.message).not.toContain('foreign key');
      }
    });

    it('should not expose stack traces in production', async () => {
      // Trigger an error
      const response = await request
        .post('/api/v1/auth/login')
        .send({
          usernameOrEmail: null,
          accountNumber: null,
          password: null,
        });

      // Should not expose stack traces
      expect(response.body.stack).toBeUndefined();
      expect(response.body.error).toBeUndefined();
    });
  });

  describe('System Information Leakage', () => {
    it('should not expose server version information', async () => {
      const response = await request
        .get('/health');

      // Health endpoint may include version, but should not expose sensitive system info
      if (response.body.version) {
        expect(typeof response.body.version).toBe('string');
        // Should not expose internal paths or system details
        expect(response.body).not.toHaveProperty('nodeVersion');
        expect(response.body).not.toHaveProperty('os');
        expect(response.body).not.toHaveProperty('platform');
      }
    });

    it('should not expose file paths in error messages', async () => {
      const response = await request
        .get('/api/v1/nonexistent');

      // Error should not contain file paths
      if (response.body.message) {
        expect(response.body.message).not.toMatch(/\/.*\.(ts|js)/);
        expect(response.body.message).not.toMatch(/C:\\/);
        expect(response.body.message).not.toMatch(/\/home\//);
      }
    });
  });

  describe('Authentication Error Messages', () => {
    it('should not reveal whether username exists', async () => {
      const response = await request
        .post('/api/v1/auth/login')
        .send({
          usernameOrEmail: 'nonexistent@example.com',
          accountNumber: '12345678',
          password: 'WrongPassword123!',
        });

      // Error message should be generic
      expect(response.body.message).not.toContain('user not found');
      expect(response.body.message).not.toContain('username');
      expect(response.body.message).not.toContain('email');
    });

    it('should not reveal password validation details', async () => {
      const response = await request
        .post('/api/v1/auth/login')
        .send({
          usernameOrEmail: 'test@example.com',
          accountNumber: '12345678',
          password: 'wrong',
        });

      // Should not reveal password requirements or validation details
      expect(response.body.message).not.toContain('password');
      expect(response.body.message).not.toContain('hash');
      expect(response.body.message).not.toContain('bcrypt');
      expect(response.body.message).not.toContain('argon');
    });
  });


  describe('Rate Limit Error Messages', () => {
    it('should not expose rate limit implementation details', async () => {
      // Trigger rate limit
      for (let i = 0; i < 10; i++) {
        await request
          .post('/api/v1/auth/login')
          .send({
            usernameOrEmail: 'test@example.com',
            accountNumber: '12345678',
            password: 'WrongPassword123!',
          });
      }

      const response = await request
        .post('/api/v1/auth/login')
        .send({
          usernameOrEmail: 'test@example.com',
          accountNumber: '12345678',
          password: 'WrongPassword123!',
        });

      if (response.status === 429) {
        // Should not expose rate limit algorithm or storage details
        expect(response.body.message).not.toContain('redis');
        expect(response.body.message).not.toContain('memory');
        expect(response.body.message).not.toContain('store');
      }
    });
  });
});
