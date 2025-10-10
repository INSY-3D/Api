import argon2 from 'argon2';
import jwt from 'jsonwebtoken';
import { v4 as uuidv4 } from 'uuid';
import { prisma } from '@/config/database';
import { config } from '@/config';
import { logger, logSecurityEvent } from '@/config/logger';
import { encryptionService } from './encryption.service';
import { otpService } from './otp.service';
import { 
  User, 
  UserSession, 
  LoginAttempt,
  SecurityEvent 
} from '@prisma/client';
import { 
  JWTPayload, 
  CreateUserDto, 
  LoginDto, 
  AuthResponse,
  UserDto 
} from '@/types';
import { 
  isValidFullName, 
  isValidSaId, 
  isValidAccountNumber, 
  isValidEmail, 
  isValidPassword,
  sanitizeString,
  sanitizeEmail 
} from '@/types/validation';
import { UserRole, EventType, SecurityRiskLevel } from '@/types/enums';

// Task 2 Compliant: Argon2id password hashing service
export class AuthService {
  private async tryDecrypt(possiblyEncrypted: string | null): Promise<string | null> {
    if (!possiblyEncrypted || possiblyEncrypted.trim() === '') return null;
    try {
      // Attempt to parse as EncryptedData JSON and decrypt
      const parsed = JSON.parse(possiblyEncrypted);
      if (!parsed || typeof parsed !== 'object') return null;
      return await encryptionService.decrypt(parsed);
    } catch (error) {
      // Fallback: treat as plain text already (for legacy data)
      // Or return null if it's clearly not valid
      if (typeof possiblyEncrypted === 'string' && possiblyEncrypted.length > 0) {
        return possiblyEncrypted;
      }
      return null;
    }
  }
  /**
   * Hash password using Argon2id (Task 2 Requirement)
   */
  async hashPassword(password: string): Promise<string> {
    try {
      const hashedPassword = await argon2.hash(password, {
        type: argon2.argon2id,
        memoryCost: config.argon2.memoryCost,
        timeCost: config.argon2.timeCost,
        parallelism: config.argon2.parallelism,
        hashLength: config.argon2.hashLength,
        // saltLength: config.argon2.saltLength, // Not needed for argon2.hash
      });

      logger.debug('Password hashed successfully with Argon2id');
      return hashedPassword;
    } catch (error) {
      logger.error('Password hashing failed', { error });
      throw new Error('Password hashing failed');
    }
  }

  /**
   * Verify password using Argon2id
   */
  async verifyPassword(password: string, hashedPassword: string): Promise<boolean> {
    try {
      const isValid = await argon2.verify(hashedPassword, password);
      logger.debug('Password verification completed', { isValid });
      return isValid;
    } catch (error) {
      logger.error('Password verification failed', { error });
      return false;
    }
  }

  /**
   * Generate JWT access token
   */
  generateAccessToken(user: User, sessionId: string): string {
    const payload: JWTPayload = {
      userId: user.id,
      email: user.emailEncrypted || undefined, // Will be decrypted when needed
      role: user.role,
      sessionId,
      iat: Math.floor(Date.now() / 1000),
      exp: Math.floor(Date.now() / 1000) + this.parseExpiry(config.jwt.expiresIn),
      iss: config.jwt.issuer,
      aud: config.jwt.audience,
    };

    return jwt.sign(payload, config.jwt.secret, {
      algorithm: 'HS256',
    });
  }

  /**
   * Generate JWT refresh token
   */
  generateRefreshToken(): string {
    return       jwt.sign(
        { 
          type: 'refresh',
          iat: Math.floor(Date.now() / 1000),
          exp: Math.floor(Date.now() / 1000) + this.parseExpiry(config.jwt.refreshExpiresIn),
        },
        config.jwt.refreshSecret,
        {
          algorithm: 'HS256',
        }
      );
  }

  /**
   * Verify JWT access token
   */
  verifyAccessToken(token: string): JWTPayload | null {
    try {
      const payload = jwt.verify(token, config.jwt.secret) as JWTPayload;

      return payload;
    } catch (error) {
      logger.warn('JWT token verification failed', { error });
      return null;
    }
  }

  /**
   * Verify JWT refresh token
   */
  verifyRefreshToken(token: string): boolean {
    try {
      jwt.verify(token, config.jwt.refreshSecret);
      return true;
    } catch (error) {
      logger.warn('Refresh token verification failed', { error });
      return false;
    }
  }

  /**
   * Register new user
   */
  async register(userData: CreateUserDto, ipAddress: string, userAgent: string): Promise<AuthResponse> {
    try {
      // Validate input data
      const validationErrors = this.validateUserData(userData);
      if (validationErrors.length > 0) {
        throw new Error(`Validation failed: ${validationErrors.join(', ')}`);
      }

      // Sanitize inputs
      const sanitizedData = {
        fullName: sanitizeString(userData.fullName, 100),
        saId: sanitizeString(userData.saId, 13),
        accountNumber: sanitizeString(userData.accountNumber, 18),
        email: userData.email ? sanitizeEmail(userData.email) : null,
        password: userData.password,
      };

      // Check for existing user
      const existingUser = await this.findUserByCredentials(
        sanitizedData.saId,
        sanitizedData.accountNumber,
        sanitizedData.email || undefined
      );

      if (existingUser) {
        await this.logSecurityEvent(null, EventType.USER_REGISTERED, 
          'Registration attempt with existing credentials', ipAddress, userAgent);
        throw new Error('User already exists with these credentials');
      }

      // Hash password
      const passwordHash = await this.hashPassword(sanitizedData.password);

      // Encrypt PII data
      const fullNameEncrypted = await encryptionService.encrypt(sanitizedData.fullName);
      const saIdEncrypted = await encryptionService.encrypt(sanitizedData.saId);
      const accountNumberEncrypted = await encryptionService.encrypt(sanitizedData.accountNumber);
      const emailEncrypted = sanitizedData.email 
        ? await encryptionService.encrypt(sanitizedData.email)
        : null;

      // Create user with encrypted PII
      const user = await prisma.user.create({
        data: {
          fullNameEncrypted: JSON.stringify(fullNameEncrypted),
          saIdEncrypted: JSON.stringify(saIdEncrypted),
          accountNumberEncrypted: JSON.stringify(accountNumberEncrypted),
          emailEncrypted: emailEncrypted ? JSON.stringify(emailEncrypted) : null,
          passwordHash,
          role: UserRole.CUSTOMER,
        },
      });

      // Create session
      const session = await this.createUserSession(user.id, ipAddress, userAgent);

      // Generate tokens
      const accessToken = this.generateAccessToken(user, session.id);
      const refreshToken = this.generateRefreshToken();

      // Update session with refresh token hash
      await prisma.userSession.update({
        where: { id: session.id },
        data: { refreshTokenHash: await this.hashPassword(refreshToken) },
      });

      // Log successful registration
      await this.logSecurityEvent(user.id, EventType.USER_REGISTERED, 
        'User registration successful', ipAddress, userAgent);

      // Return response
      return {
        message: 'Registration successful',
        user: await this.mapUserToDto(user),
        accessToken,
        refreshToken,
        expiresIn: config.jwt.expiresIn,
      };
    } catch (error) {
      logger.error('User registration failed', { error });
      throw error;
    }
  }

  /**
   * Authenticate user login
   */
  async login(loginData: LoginDto, ipAddress: string, userAgent: string): Promise<AuthResponse> {
    try {
      // Validate input data
      if (!loginData.usernameOrEmail || !loginData.accountNumber || !loginData.password) {
        throw new Error('Missing required fields');
      }

      // Sanitize inputs
      const sanitizedData = {
        usernameOrEmail: sanitizeString(loginData.usernameOrEmail, 254),
        accountNumber: sanitizeString(loginData.accountNumber, 18),
        password: loginData.password,
        otp: loginData.otp,
      };

      // Find user by credentials
      logger.info('🔍 DEBUG: Attempting login', {
        usernameOrEmail: sanitizedData.usernameOrEmail,
        accountNumber: sanitizedData.accountNumber,
      });
      
      const user = await this.findUserByLoginCredentials(
        sanitizedData.usernameOrEmail,
        sanitizedData.accountNumber
      );

      if (!user) {
        logger.warn('🔍 DEBUG: User not found during login', {
          usernameOrEmail: sanitizedData.usernameOrEmail,
          accountNumber: sanitizedData.accountNumber,
        });
        await this.logLoginAttempt(sanitizedData.usernameOrEmail, ipAddress, userAgent, false, 'User not found');
        await this.logSecurityEvent(null, EventType.LOGIN_FAILED, 
          'Login attempt with invalid credentials', ipAddress, userAgent);
        throw new Error('Invalid credentials');
      }
      
      logger.info('🔍 DEBUG: User found', { userId: user.id, role: user.role });

      // Check if account is locked
      if (user.lockedUntil && user.lockedUntil > new Date()) {
        await this.logSecurityEvent(user.id, EventType.ACCOUNT_LOCKED, 
          'Login attempt on locked account', ipAddress, userAgent);
        throw new Error('Account is temporarily locked due to too many failed attempts');
      }

      // Verify password
      logger.info('🔍 DEBUG: Verifying password for user', { userId: user.id });
      const isPasswordValid = await this.verifyPassword(sanitizedData.password, user.passwordHash);
      logger.info('🔍 DEBUG: Password verification result', { userId: user.id, isValid: isPasswordValid });
      
      if (!isPasswordValid) {
        await this.updateFailedLoginAttempts(user.id);
        await this.logLoginAttempt(sanitizedData.usernameOrEmail, ipAddress, userAgent, false, 'Invalid password');
        await this.logSecurityEvent(user.id, EventType.LOGIN_FAILED, 
          'Login attempt with invalid password', ipAddress, userAgent);
        throw new Error('Invalid credentials');
      }

      // OTP-based authentication flow (TEMPORARILY DISABLED FOR TESTING)
      // const isStaffOrAdmin = user.role === 'staff' || user.role === 'admin';
      
      // Log that OTP is disabled
      await this.logSecurityEvent(user.id, EventType.USER_LOGIN, 
        '⚠️ Login without OTP - TEMPORARILY DISABLED FOR TESTING', ipAddress, userAgent);
      
      /* COMMENTED OUT - OTP DISABLED FOR TESTING
      if (!isStaffOrAdmin) {
        // Only require OTP for customers
        const decryptedEmail = await this.tryDecrypt(user.emailEncrypted ?? null);
        
        if (!sanitizedData.otp) {
          // User hasn't provided OTP yet, need to send it
          if (decryptedEmail) {
            // User has registered email, send OTP to it
            const otpResult = await otpService.generateAndSendOtp(
              decryptedEmail, 
              user.id, 
              'login'
            );
            
            if (!otpResult.success) {
              throw new Error('Failed to send OTP. Please try again.');
            }

            return {
              message: otpResult.message,
              user: await this.mapUserToDto(user),
              accessToken: '',
              refreshToken: '',
              expiresIn: '',
              mfa: 'required',
              hasEmail: true,
            };
          } else {
            // User doesn't have registered email, they need to provide one
            return {
              message: 'Please provide an email to receive OTP',
              user: await this.mapUserToDto(user),
              accessToken: '',
              refreshToken: '',
              expiresIn: '',
              mfa: 'required',
              hasEmail: false,
            };
          }
        }

        // Verify OTP if provided
        // Use registered email if available, otherwise use email from request (tempEmail for backwards compatibility)
        const emailForVerification = decryptedEmail || loginData.email || loginData.tempEmail;
        
        if (!emailForVerification) {
          throw new Error('Email is required for OTP verification');
        }

        const otpVerification = await otpService.verifyOtp(
          emailForVerification,
          sanitizedData.otp,
          'login'
        );

        if (!otpVerification.valid) {
          await this.logSecurityEvent(user.id, EventType.LOGIN_FAILED, 
            'Login attempt with invalid OTP', ipAddress, userAgent);
          throw new Error(otpVerification.message);
        }
      } else {
        // Staff/Admin: Log that OTP was skipped
        await this.logSecurityEvent(user.id, EventType.USER_LOGIN, 
          'Staff login - OTP skipped', ipAddress, userAgent);
      }
      */

      // Reset failed login attempts
      await prisma.user.update({
        where: { id: user.id },
        data: {
          failedLoginAttempts: 0,
          lockedUntil: null,
        },
      });

      // Check for unknown device
      const knownDevice = await prisma.userSession.findFirst({
        where: {
          userId: user.id,
          ipAddress,
          isActive: true,
        },
      });

      // Create new session
      const session = await this.createUserSession(user.id, ipAddress, userAgent);

      // Generate tokens
      const accessToken = this.generateAccessToken(user, session.id);
      const refreshToken = this.generateRefreshToken();

      // Update session with refresh token hash
      await prisma.userSession.update({
        where: { id: session.id },
        data: { refreshTokenHash: await this.hashPassword(refreshToken) },
      });

      // Log successful login
      await this.logLoginAttempt(sanitizedData.usernameOrEmail, ipAddress, userAgent, true);
      await this.logSecurityEvent(user.id, EventType.USER_LOGIN, 
        'User login successful', ipAddress, userAgent);

      // Return response
      return {
        message: 'Login successful',
        user: await this.mapUserToDto(user),
        accessToken,
        refreshToken,
        expiresIn: config.jwt.expiresIn,
        unknownDevice: !knownDevice,
      };
    } catch (error) {
      logger.error('User login failed', { error });
      throw error;
    }
  }

  /**
   * Get user information (decrypted)
   */
  async getUserInfo(userId: string): Promise<UserDto | null> {
    try {
      const user = await prisma.user.findUnique({
        where: { id: userId },
      });

      if (!user) {
        return null;
      }

      return await this.mapUserToDto(user);
    } catch (error) {
      logger.error('Failed to get user info', { error, userId });
      throw error;
    }
  }

  /**
   * Logout user
   */
  async logout(userId: string, sessionId: string): Promise<void> {
    try {
      // Deactivate session
      await prisma.userSession.update({
        where: { id: sessionId },
        data: { isActive: false },
      });

      // Log logout
      await this.logSecurityEvent(userId, EventType.USER_LOGOUT, 
        'User logout successful');

      logger.info('User logged out successfully', { userId, sessionId });
    } catch (error) {
      logger.error('User logout failed', { error });
      throw error;
    }
  }

  /**
   * Get user by ID
   */
  async getUserById(userId: string): Promise<User | null> {
    try {
      return await prisma.user.findUnique({
        where: { id: userId },
      });
    } catch (error) {
      logger.error('Failed to get user by ID', { error, userId });
      return null;
    }
  }

  /**
   * Get user session by ID
   */
  async getUserSession(sessionId: string): Promise<UserSession | null> {
    try {
      return await prisma.userSession.findUnique({
        where: { id: sessionId },
        include: { user: true },
      });
    } catch (error) {
      logger.error('Failed to get user session', { error, sessionId });
      return null;
    }
  }

  // Private helper methods

  private validateUserData(userData: CreateUserDto): string[] {
    const errors: string[] = [];

    if (!isValidFullName(userData.fullName)) {
      errors.push('Invalid full name format');
    }

    if (!isValidSaId(userData.saId)) {
      errors.push('Invalid SA ID format');
    }

    if (!isValidAccountNumber(userData.accountNumber)) {
      errors.push('Invalid account number format');
    }

    if (userData.email && !isValidEmail(userData.email)) {
      errors.push('Invalid email format');
    }

    if (!isValidPassword(userData.password)) {
      errors.push('Invalid password format');
    }

    return errors;
  }

  private async findUserByCredentials(saId: string, accountNumber: string, email?: string): Promise<User | null> {
    try {
      // Get all active users
      const users = await prisma.user.findMany({
        where: { isActive: true },
      });

      // Decrypt and compare credentials
      for (const user of users) {
        try {
          // Decrypt PII fields (support legacy plain strings)
          const decryptedSaId = await this.tryDecrypt(user.saIdEncrypted);
          const decryptedAccountNumber = await this.tryDecrypt(user.accountNumberEncrypted);
          const decryptedEmail = await this.tryDecrypt(user.emailEncrypted ?? null);

          // Check if any credentials match
          const saIdMatch = decryptedSaId && (decryptedSaId === saId);
          const accountMatch = decryptedAccountNumber && (decryptedAccountNumber === accountNumber);
          const emailMatch = email && decryptedEmail && 
            (decryptedEmail.toLowerCase() === email.toLowerCase());

          if (saIdMatch || accountMatch || emailMatch) {
            return user;
          }
        } catch (decryptError) {
          logger.warn('Failed to decrypt user credentials', { 
            userId: user.id, 
            error: decryptError 
          });
          continue;
        }
      }

      return null;
    } catch (error) {
      logger.error('Failed to find user by credentials', { error });
      return null;
    }
  }

  private async findUserByLoginCredentials(usernameOrEmail: string, accountNumber: string): Promise<User | null> {
    try {
      logger.info('🔍 DEBUG: Finding user by credentials', { 
        usernameOrEmail, 
        accountNumber 
      });
      
      // Get all active users
      const users = await prisma.user.findMany({
        where: { isActive: true },
      });
      
      logger.info(`🔍 DEBUG: Found ${users.length} active users in database`);

      // Decrypt and compare credentials
      for (const user of users) {
        try {
          // Decrypt email, account number, and SA ID
          const decryptedEmail = await this.tryDecrypt(user.emailEncrypted ?? null);
          const decryptedAccountNumber = await this.tryDecrypt(user.accountNumberEncrypted);
          const decryptedSaId = await this.tryDecrypt(user.saIdEncrypted);

          logger.info('🔍 DEBUG: Checking user', { 
            userId: user.id,
            decryptedEmail,
            decryptedAccountNumber,
            decryptedSaId
          });

          // Check if identifier matches email OR account number OR SA ID,
          // and the provided accountNumber matches the stored account number
          const normalizedIdentifier = usernameOrEmail.trim();
          const emailMatch = decryptedEmail && 
            (decryptedEmail.toLowerCase() === normalizedIdentifier.toLowerCase());
          const usernameIsAccount = decryptedAccountNumber && 
            (decryptedAccountNumber === normalizedIdentifier);
          const usernameIsSaId = decryptedSaId && 
            (decryptedSaId === normalizedIdentifier);
          const accountMatch = decryptedAccountNumber && 
            (decryptedAccountNumber === accountNumber.trim());

          logger.info('🔍 DEBUG: Match results', {
            userId: user.id,
            emailMatch,
            usernameIsAccount,
            usernameIsSaId,
            accountMatch,
            wouldMatch: (emailMatch || usernameIsAccount || usernameIsSaId) && accountMatch
          });

          if ((emailMatch || usernameIsAccount || usernameIsSaId) && accountMatch) {
            logger.info('🔍 DEBUG: USER MATCHED!', { userId: user.id });
            return user;
          }
        } catch (decryptError) {
          logger.warn('Failed to decrypt user credentials', { 
            userId: user.id, 
            error: decryptError 
          });
          continue;
        }
      }

      logger.warn('🔍 DEBUG: NO USER MATCHED');
      return null;
    } catch (error) {
      logger.error('Failed to find user by login credentials', { error });
      return null;
    }
  }

  private async createUserSession(userId: string, ipAddress: string, userAgent: string): Promise<UserSession> {
    const expiresAt = new Date();
    expiresAt.setDate(expiresAt.getDate() + 7); // 7 days

    return await prisma.userSession.create({
      data: {
        userId,
        refreshTokenHash: '', // Will be updated after token generation
        ipAddress,
        userAgent,
        expiresAt,
      },
    });
  }

  private async updateFailedLoginAttempts(userId: string): Promise<void> {
    try {
      const user = await prisma.user.findUnique({ where: { id: userId } });
      if (!user) return;

      const newAttempts = user.failedLoginAttempts + 1;
      const updateData: any = { failedLoginAttempts: newAttempts };

      // Lock account after 5 failed attempts
      if (newAttempts >= 5) {
        updateData.lockedUntil = new Date(Date.now() + 30 * 60 * 1000); // 30 minutes
      }

      await prisma.user.update({
        where: { id: userId },
        data: updateData,
      });
    } catch (error) {
      logger.error('Failed to update failed login attempts', { error, userId });
    }
  }

  private async logLoginAttempt(
    identifier: string,
    ipAddress: string,
    userAgent: string,
    success: boolean,
    failureReason?: string
  ): Promise<void> {
    try {
      await prisma.loginAttempt.create({
        data: {
          identifier,
          ipAddress,
          userAgent,
          success,
          failureReason,
        },
      });
    } catch (error) {
      logger.error('Failed to log login attempt', { error });
    }
  }

  private async logSecurityEvent(
    userId: string | null,
    eventType: EventType,
    description: string,
    ipAddress?: string,
    userAgent?: string
  ): Promise<void> {
    try {
      await prisma.securityEvent.create({
        data: {
          userId,
          eventType,
          description,
          ipAddress,
          userAgent,
        },
      });

      // Also log to security logger
      logSecurityEvent(eventType, description, {
        userId,
        ipAddress,
        userAgent,
      });
    } catch (error) {
      logger.error('Failed to log security event', { error });
    }
  }

  private async mapUserToDto(user: User): Promise<UserDto> {
    try {
      const fullName = user.fullNameEncrypted ? 
        await this.tryDecrypt(user.fullNameEncrypted) || '' : '';
      const email = user.emailEncrypted ? 
        await this.tryDecrypt(user.emailEncrypted) || undefined : undefined;

      return {
        id: user.id,
        fullName,
        email,
        role: user.role,
        createdAt: user.createdAt,
      };
    } catch (error) {
      logger.error('Failed to decrypt user data for DTO', { error, userId: user.id });
      return {
        id: user.id,
        fullName: '[Encrypted]',
        email: undefined,
        role: user.role,
        createdAt: user.createdAt,
      };
    }
  }

  private parseExpiry(expiry: string): number {
    const unit = expiry.slice(-1);
    const value = parseInt(expiry.slice(0, -1), 10);

    switch (unit) {
      case 's': return value;
      case 'm': return value * 60;
      case 'h': return value * 60 * 60;
      case 'd': return value * 24 * 60 * 60;
      default: return 15 * 60; // Default 15 minutes
    }
  }
}

// Export singleton instance
export const authService = new AuthService();
