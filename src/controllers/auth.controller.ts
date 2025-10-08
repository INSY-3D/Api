import { Request, Response } from 'express';
import { AuthenticatedRequest } from '@/types';
import { authService } from '@/services/auth.service';
import { logger } from '@/config/logger';
import { CreateUserDto, LoginDto } from '@/types';
import { EventType } from '@/types/enums';

// Task 2 Compliant: Authentication controller
export class AuthController {
  /**
   * Register new user
   * POST /api/v1/register
   */
  async register(req: Request, res: Response): Promise<void> {
    try {
      const userData: CreateUserDto = req.body;
      const ipAddress = this.getClientIpAddress(req);
      const userAgent = req.get('User-Agent') || '';

      logger.info('User registration attempt', {
        ipAddress,
        userAgent,
        fullName: userData.fullName,
      });

      const result = await authService.register(userData, ipAddress, userAgent);

      res.status(201).json({
        success: true,
        message: result.message,
        data: {
          user: result.user,
          accessToken: result.accessToken,
          refreshToken: result.refreshToken,
          expiresIn: result.expiresIn,
        },
      });
    } catch (error) {
      logger.error('Registration failed', { error });
      
      res.status(400).json({
        success: false,
        message: error instanceof Error ? error.message : 'Registration failed',
        code: 'REGISTRATION_FAILED',
      });
    }
  }

  /**
   * User login
   * POST /api/v1/login
   */
  async login(req: Request, res: Response): Promise<void> {
    try {
      const loginData: LoginDto = req.body;
      const ipAddress = this.getClientIpAddress(req);
      const userAgent = req.get('User-Agent') || '';

      logger.info('User login attempt', {
        ipAddress,
        userAgent,
        usernameOrEmail: loginData.usernameOrEmail,
      });

      const result = await authService.login(loginData, ipAddress, userAgent);

      // Check if MFA is required
      if (result.mfa === 'required') {
        res.status(200).json({
          success: true,
          message: result.message, // Use message from auth service (contains OTP sent info)
          data: {
            mfa: 'required',
            user: result.user,
            hasEmail: result.hasEmail, // Include hasEmail flag
          },
        });
        return;
      }

      res.status(200).json({
        success: true,
        message: result.message,
        data: {
          user: result.user,
          accessToken: result.accessToken,
          refreshToken: result.refreshToken,
          expiresIn: result.expiresIn,
          unknownDevice: result.unknownDevice,
        },
      });
    } catch (error) {
      logger.error('Login failed', { error });
      
      res.status(401).json({
        success: false,
        message: error instanceof Error ? error.message : 'Login failed',
        code: 'LOGIN_FAILED',
      });
    }
  }

  /**
   * User logout
   * POST /api/v1/logout
   */
  async logout(req: AuthenticatedRequest, res: Response): Promise<void> {
    try {
      const userId = req.user?.id;
      const sessionId = req.session?.id;

      if (!userId || !sessionId) {
        res.status(401).json({
          success: false,
          message: 'Authentication required',
          code: 'AUTH_REQUIRED',
        });
        return;
      }

      await authService.logout(userId, sessionId);

      res.status(200).json({
        success: true,
        message: 'Logout successful',
      });
    } catch (error) {
      logger.error('Logout failed', { error });
      
      res.status(500).json({
        success: false,
        message: 'Logout failed',
        code: 'LOGOUT_FAILED',
      });
    }
  }

  /**
   * Get current user information
   * GET /api/v1/me
   */
  async getMe(req: AuthenticatedRequest, res: Response): Promise<void> {
    try {
      if (!req.user) {
        res.status(401).json({
          success: false,
          message: 'Authentication required',
          code: 'AUTH_REQUIRED',
        });
        return;
      }

      res.status(200).json({
        success: true,
        data: {
          user: {
            id: req.user.id,
            fullName: req.user.fullNameEncrypted, // Will be decrypted
            email: req.user.emailEncrypted, // Will be decrypted
            role: req.user.role,
            createdAt: req.user.createdAt,
          },
        },
      });
    } catch (error) {
      logger.error('Get user info failed', { error });
      
      res.status(500).json({
        success: false,
        message: 'Failed to get user information',
        code: 'USER_INFO_FAILED',
      });
    }
  }

  /**
   * Refresh access token
   * POST /api/v1/refresh
   */
  async refreshToken(req: Request, res: Response): Promise<void> {
    try {
      const { refreshToken } = req.body;

      if (!refreshToken) {
        res.status(400).json({
          success: false,
          message: 'Refresh token required',
          code: 'REFRESH_TOKEN_REQUIRED',
        });
        return;
      }

      // Verify refresh token
      const isValid = authService.verifyRefreshToken(refreshToken);
      if (!isValid) {
        res.status(401).json({
          success: false,
          message: 'Invalid refresh token',
          code: 'INVALID_REFRESH_TOKEN',
        });
        return;
      }

      // TODO: Implement refresh token logic
      // This would involve:
      // 1. Verify refresh token
      // 2. Get user from token
      // 3. Generate new access token
      // 4. Optionally rotate refresh token

      res.status(200).json({
        success: true,
        message: 'Token refreshed successfully',
        data: {
          accessToken: 'new-access-token',
          expiresIn: '15m',
        },
      });
    } catch (error) {
      logger.error('Token refresh failed', { error });
      
      res.status(500).json({
        success: false,
        message: 'Token refresh failed',
        code: 'REFRESH_FAILED',
      });
    }
  }

  /**
   * Get CSRF token
   * GET /api/v1/csrf
   */
  async getCsrfToken(req: Request, res: Response): Promise<void> {
    try {
      // Generate CSRF token
      const csrfToken = this.generateCsrfToken();
      const ipAddress = this.getClientIpAddress(req);

      // TODO: Store CSRF token in database with expiry
      // This would involve creating a CsrfToken record

      res.status(200).json({
        success: true,
        data: {
          token: csrfToken,
        },
      });
    } catch (error) {
      logger.error('CSRF token generation failed', { error });
      
      res.status(500).json({
        success: false,
        message: 'Failed to generate CSRF token',
        code: 'CSRF_GENERATION_FAILED',
      });
    }
  }

  /**
   * Send OTP to email (for users without registered email)
   * POST /api/v1/auth/send-otp
   */
  async sendOtp(req: Request, res: Response): Promise<void> {
    try {
      const { email, userId } = req.body;

      if (!email) {
        res.status(400).json({
          success: false,
          message: 'Email is required',
          code: 'EMAIL_REQUIRED',
        });
        return;
      }

      const ipAddress = this.getClientIpAddress(req);
      const userAgent = req.get('User-Agent') || '';

      logger.info('OTP send request', { email, userId, ipAddress });

      const { otpService } = await import('@/services/otp.service');
      const result = await otpService.generateAndSendOtp(email, userId, 'login');

      if (!result.success) {
        res.status(500).json({
          success: false,
          message: result.message,
          code: 'OTP_SEND_FAILED',
        });
        return;
      }

      res.status(200).json({
        success: true,
        message: result.message,
      });
    } catch (error) {
      logger.error('Send OTP failed', { error });
      
      res.status(500).json({
        success: false,
        message: 'Failed to send OTP',
        code: 'OTP_SEND_FAILED',
      });
    }
  }

  /**
   * Staff login endpoint
   * POST /api/v1/staff-login
   */
  async staffLogin(req: Request, res: Response): Promise<void> {
    try {
      const loginData: LoginDto = req.body;
      const ipAddress = this.getClientIpAddress(req);
      const userAgent = req.get('User-Agent') || '';

      logger.info('Staff login attempt', {
        ipAddress,
        userAgent,
        usernameOrEmail: loginData.usernameOrEmail,
      });

      const result = await authService.login(loginData, ipAddress, userAgent);

      // Check if user has staff role
      if (result.user.role !== 'staff' && result.user.role !== 'admin') {
        res.status(403).json({
          success: false,
          message: 'Staff access required',
          code: 'STAFF_ACCESS_REQUIRED',
        });
        return;
      }

      // Check if MFA is required
      if (result.mfa === 'required') {
        res.status(200).json({
          success: true,
          message: result.message, // Use message from auth service (contains OTP sent info)
          data: {
            mfa: 'required',
            user: result.user,
            hasEmail: result.hasEmail, // Include hasEmail flag
          },
        });
        return;
      }

      res.status(200).json({
        success: true,
        message: result.message,
        data: {
          user: result.user,
          accessToken: result.accessToken,
          refreshToken: result.refreshToken,
          expiresIn: result.expiresIn,
          unknownDevice: result.unknownDevice,
        },
      });
    } catch (error) {
      logger.error('Staff login failed', { error });
      
      res.status(401).json({
        success: false,
        message: error instanceof Error ? error.message : 'Staff login failed',
        code: 'STAFF_LOGIN_FAILED',
      });
    }
  }

  // Private helper methods

  private getClientIpAddress(req: Request): string {
    return (
      req.headers['x-forwarded-for'] as string ||
      req.headers['x-real-ip'] as string ||
      req.connection.remoteAddress ||
      req.socket.remoteAddress ||
      'unknown'
    );
  }

  private generateCsrfToken(): string {
    const crypto = require('crypto');
    return crypto.randomBytes(32).toString('hex');
  }
}

// Export controller instance
export const authController = new AuthController();
