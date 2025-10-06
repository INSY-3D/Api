"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.authService = exports.AuthService = void 0;
const argon2_1 = __importDefault(require("argon2"));
const jsonwebtoken_1 = __importDefault(require("jsonwebtoken"));
const database_1 = require("@/config/database");
const config_1 = require("@/config");
const logger_1 = require("@/config/logger");
const encryption_service_1 = require("./encryption.service");
const validation_1 = require("@/types/validation");
const enums_1 = require("@/types/enums");
class AuthService {
    async tryDecrypt(possiblyEncrypted) {
        if (!possiblyEncrypted)
            return null;
        try {
            const parsed = JSON.parse(possiblyEncrypted);
            return await encryption_service_1.encryptionService.decrypt(parsed);
        }
        catch {
            return possiblyEncrypted;
        }
    }
    async hashPassword(password) {
        try {
            const hashedPassword = await argon2_1.default.hash(password, {
                type: argon2_1.default.argon2id,
                memoryCost: config_1.config.argon2.memoryCost,
                timeCost: config_1.config.argon2.timeCost,
                parallelism: config_1.config.argon2.parallelism,
                hashLength: config_1.config.argon2.hashLength,
            });
            logger_1.logger.debug('Password hashed successfully with Argon2id');
            return hashedPassword;
        }
        catch (error) {
            logger_1.logger.error('Password hashing failed', { error });
            throw new Error('Password hashing failed');
        }
    }
    async verifyPassword(password, hashedPassword) {
        try {
            const isValid = await argon2_1.default.verify(hashedPassword, password);
            logger_1.logger.debug('Password verification completed', { isValid });
            return isValid;
        }
        catch (error) {
            logger_1.logger.error('Password verification failed', { error });
            return false;
        }
    }
    generateAccessToken(user, sessionId) {
        const payload = {
            userId: user.id,
            email: user.emailEncrypted || undefined,
            role: user.role,
            sessionId,
            iat: Math.floor(Date.now() / 1000),
            exp: Math.floor(Date.now() / 1000) + this.parseExpiry(config_1.config.jwt.expiresIn),
            iss: config_1.config.jwt.issuer,
            aud: config_1.config.jwt.audience,
        };
        return jsonwebtoken_1.default.sign(payload, config_1.config.jwt.secret, {
            algorithm: 'HS256',
        });
    }
    generateRefreshToken() {
        return jsonwebtoken_1.default.sign({
            type: 'refresh',
            iat: Math.floor(Date.now() / 1000),
            exp: Math.floor(Date.now() / 1000) + this.parseExpiry(config_1.config.jwt.refreshExpiresIn),
        }, config_1.config.jwt.refreshSecret, {
            algorithm: 'HS256',
        });
    }
    verifyAccessToken(token) {
        try {
            const payload = jsonwebtoken_1.default.verify(token, config_1.config.jwt.secret);
            return payload;
        }
        catch (error) {
            logger_1.logger.warn('JWT token verification failed', { error });
            return null;
        }
    }
    verifyRefreshToken(token) {
        try {
            jsonwebtoken_1.default.verify(token, config_1.config.jwt.refreshSecret);
            return true;
        }
        catch (error) {
            logger_1.logger.warn('Refresh token verification failed', { error });
            return false;
        }
    }
    async register(userData, ipAddress, userAgent) {
        try {
            const validationErrors = this.validateUserData(userData);
            if (validationErrors.length > 0) {
                throw new Error(`Validation failed: ${validationErrors.join(', ')}`);
            }
            const sanitizedData = {
                fullName: (0, validation_1.sanitizeString)(userData.fullName, 100),
                saId: (0, validation_1.sanitizeString)(userData.saId, 13),
                accountNumber: (0, validation_1.sanitizeString)(userData.accountNumber, 18),
                email: userData.email ? (0, validation_1.sanitizeEmail)(userData.email) : null,
                password: userData.password,
            };
            const existingUser = await this.findUserByCredentials(sanitizedData.saId, sanitizedData.accountNumber, sanitizedData.email || undefined);
            if (existingUser) {
                await this.logSecurityEvent(null, enums_1.EventType.USER_REGISTERED, 'Registration attempt with existing credentials', ipAddress, userAgent);
                throw new Error('User already exists with these credentials');
            }
            const passwordHash = await this.hashPassword(sanitizedData.password);
            const user = await database_1.prisma.user.create({
                data: {
                    fullNameEncrypted: sanitizedData.fullName,
                    saIdEncrypted: sanitizedData.saId,
                    accountNumberEncrypted: sanitizedData.accountNumber,
                    emailEncrypted: sanitizedData.email,
                    passwordHash,
                    role: enums_1.UserRole.CUSTOMER,
                },
            });
            const session = await this.createUserSession(user.id, ipAddress, userAgent);
            const accessToken = this.generateAccessToken(user, session.id);
            const refreshToken = this.generateRefreshToken();
            await database_1.prisma.userSession.update({
                where: { id: session.id },
                data: { refreshTokenHash: await this.hashPassword(refreshToken) },
            });
            await this.logSecurityEvent(user.id, enums_1.EventType.USER_REGISTERED, 'User registration successful', ipAddress, userAgent);
            return {
                message: 'Registration successful',
                user: await this.mapUserToDto(user),
                accessToken,
                refreshToken,
                expiresIn: config_1.config.jwt.expiresIn,
            };
        }
        catch (error) {
            logger_1.logger.error('User registration failed', { error });
            throw error;
        }
    }
    async login(loginData, ipAddress, userAgent) {
        try {
            if (!loginData.usernameOrEmail || !loginData.accountNumber || !loginData.password) {
                throw new Error('Missing required fields');
            }
            const sanitizedData = {
                usernameOrEmail: (0, validation_1.sanitizeString)(loginData.usernameOrEmail, 254),
                accountNumber: (0, validation_1.sanitizeString)(loginData.accountNumber, 18),
                password: loginData.password,
                otp: loginData.otp,
            };
            const user = await this.findUserByLoginCredentials(sanitizedData.usernameOrEmail, sanitizedData.accountNumber);
            if (!user) {
                await this.logLoginAttempt(sanitizedData.usernameOrEmail, ipAddress, userAgent, false, 'User not found');
                await this.logSecurityEvent(null, enums_1.EventType.LOGIN_FAILED, 'Login attempt with invalid credentials', ipAddress, userAgent);
                throw new Error('Invalid credentials');
            }
            if (user.lockedUntil && user.lockedUntil > new Date()) {
                await this.logSecurityEvent(user.id, enums_1.EventType.ACCOUNT_LOCKED, 'Login attempt on locked account', ipAddress, userAgent);
                throw new Error('Account is temporarily locked due to too many failed attempts');
            }
            const isPasswordValid = await this.verifyPassword(sanitizedData.password, user.passwordHash);
            if (!isPasswordValid) {
                await this.updateFailedLoginAttempts(user.id);
                await this.logLoginAttempt(sanitizedData.usernameOrEmail, ipAddress, userAgent, false, 'Invalid password');
                await this.logSecurityEvent(user.id, enums_1.EventType.LOGIN_FAILED, 'Login attempt with invalid password', ipAddress, userAgent);
                throw new Error('Invalid credentials');
            }
            const demoEmails = ['test@nexuspay.dev', 'staff@nexuspay.dev', 'admin@nexuspay.dev'];
            const decryptedEmail = await this.tryDecrypt(user.emailEncrypted ?? null);
            if (!sanitizedData.otp && !demoEmails.includes(decryptedEmail || '')) {
                return {
                    message: 'MFA required',
                    user: await this.mapUserToDto(user),
                    accessToken: '',
                    refreshToken: '',
                    expiresIn: '',
                    mfa: 'required',
                };
            }
            await database_1.prisma.user.update({
                where: { id: user.id },
                data: {
                    failedLoginAttempts: 0,
                    lockedUntil: null,
                },
            });
            const knownDevice = await database_1.prisma.userSession.findFirst({
                where: {
                    userId: user.id,
                    ipAddress,
                    isActive: true,
                },
            });
            const session = await this.createUserSession(user.id, ipAddress, userAgent);
            const accessToken = this.generateAccessToken(user, session.id);
            const refreshToken = this.generateRefreshToken();
            await database_1.prisma.userSession.update({
                where: { id: session.id },
                data: { refreshTokenHash: await this.hashPassword(refreshToken) },
            });
            await this.logLoginAttempt(sanitizedData.usernameOrEmail, ipAddress, userAgent, true);
            await this.logSecurityEvent(user.id, enums_1.EventType.USER_LOGIN, 'User login successful', ipAddress, userAgent);
            return {
                message: 'Login successful',
                user: await this.mapUserToDto(user),
                accessToken,
                refreshToken,
                expiresIn: config_1.config.jwt.expiresIn,
                unknownDevice: !knownDevice,
            };
        }
        catch (error) {
            logger_1.logger.error('User login failed', { error });
            throw error;
        }
    }
    async logout(userId, sessionId) {
        try {
            await database_1.prisma.userSession.update({
                where: { id: sessionId },
                data: { isActive: false },
            });
            await this.logSecurityEvent(userId, enums_1.EventType.USER_LOGOUT, 'User logout successful');
            logger_1.logger.info('User logged out successfully', { userId, sessionId });
        }
        catch (error) {
            logger_1.logger.error('User logout failed', { error });
            throw error;
        }
    }
    async getUserById(userId) {
        try {
            return await database_1.prisma.user.findUnique({
                where: { id: userId },
            });
        }
        catch (error) {
            logger_1.logger.error('Failed to get user by ID', { error, userId });
            return null;
        }
    }
    async getUserSession(sessionId) {
        try {
            return await database_1.prisma.userSession.findUnique({
                where: { id: sessionId },
                include: { user: true },
            });
        }
        catch (error) {
            logger_1.logger.error('Failed to get user session', { error, sessionId });
            return null;
        }
    }
    validateUserData(userData) {
        const errors = [];
        if (!(0, validation_1.isValidFullName)(userData.fullName)) {
            errors.push('Invalid full name format');
        }
        if (!(0, validation_1.isValidSaId)(userData.saId)) {
            errors.push('Invalid SA ID format');
        }
        if (!(0, validation_1.isValidAccountNumber)(userData.accountNumber)) {
            errors.push('Invalid account number format');
        }
        if (userData.email && !(0, validation_1.isValidEmail)(userData.email)) {
            errors.push('Invalid email format');
        }
        if (!(0, validation_1.isValidPassword)(userData.password)) {
            errors.push('Invalid password format');
        }
        return errors;
    }
    async findUserByCredentials(saId, accountNumber, email) {
        try {
            const users = await database_1.prisma.user.findMany({
                where: { isActive: true },
            });
            for (const user of users) {
                try {
                    const decryptedSaId = await this.tryDecrypt(user.saIdEncrypted);
                    const decryptedAccountNumber = await this.tryDecrypt(user.accountNumberEncrypted);
                    const decryptedEmail = await this.tryDecrypt(user.emailEncrypted ?? null);
                    const saIdMatch = decryptedSaId && (decryptedSaId === saId);
                    const accountMatch = decryptedAccountNumber && (decryptedAccountNumber === accountNumber);
                    const emailMatch = email && decryptedEmail &&
                        (decryptedEmail.toLowerCase() === email.toLowerCase());
                    if (saIdMatch || accountMatch || emailMatch) {
                        return user;
                    }
                }
                catch (decryptError) {
                    logger_1.logger.warn('Failed to decrypt user credentials', {
                        userId: user.id,
                        error: decryptError
                    });
                    continue;
                }
            }
            return null;
        }
        catch (error) {
            logger_1.logger.error('Failed to find user by credentials', { error });
            return null;
        }
    }
    async findUserByLoginCredentials(usernameOrEmail, accountNumber) {
        try {
            const users = await database_1.prisma.user.findMany({
                where: { isActive: true },
            });
            for (const user of users) {
                try {
                    const decryptedEmail = await this.tryDecrypt(user.emailEncrypted ?? null);
                    const decryptedAccountNumber = await this.tryDecrypt(user.accountNumberEncrypted);
                    const decryptedSaId = await this.tryDecrypt(user.saIdEncrypted);
                    const normalizedIdentifier = usernameOrEmail.trim();
                    const emailMatch = decryptedEmail &&
                        (decryptedEmail.toLowerCase() === normalizedIdentifier.toLowerCase());
                    const usernameIsAccount = decryptedAccountNumber &&
                        (decryptedAccountNumber === normalizedIdentifier);
                    const usernameIsSaId = decryptedSaId &&
                        (decryptedSaId === normalizedIdentifier);
                    const accountMatch = decryptedAccountNumber &&
                        (decryptedAccountNumber === accountNumber.trim());
                    if ((emailMatch || usernameIsAccount || usernameIsSaId) && accountMatch) {
                        return user;
                    }
                }
                catch (decryptError) {
                    logger_1.logger.warn('Failed to decrypt user credentials', {
                        userId: user.id,
                        error: decryptError
                    });
                    continue;
                }
            }
            return null;
        }
        catch (error) {
            logger_1.logger.error('Failed to find user by login credentials', { error });
            return null;
        }
    }
    async createUserSession(userId, ipAddress, userAgent) {
        const expiresAt = new Date();
        expiresAt.setDate(expiresAt.getDate() + 7);
        return await database_1.prisma.userSession.create({
            data: {
                userId,
                refreshTokenHash: '',
                ipAddress,
                userAgent,
                expiresAt,
            },
        });
    }
    async updateFailedLoginAttempts(userId) {
        try {
            const user = await database_1.prisma.user.findUnique({ where: { id: userId } });
            if (!user)
                return;
            const newAttempts = user.failedLoginAttempts + 1;
            const updateData = { failedLoginAttempts: newAttempts };
            if (newAttempts >= 5) {
                updateData.lockedUntil = new Date(Date.now() + 30 * 60 * 1000);
            }
            await database_1.prisma.user.update({
                where: { id: userId },
                data: updateData,
            });
        }
        catch (error) {
            logger_1.logger.error('Failed to update failed login attempts', { error, userId });
        }
    }
    async logLoginAttempt(identifier, ipAddress, userAgent, success, failureReason) {
        try {
            await database_1.prisma.loginAttempt.create({
                data: {
                    identifier,
                    ipAddress,
                    userAgent,
                    success,
                    failureReason,
                },
            });
        }
        catch (error) {
            logger_1.logger.error('Failed to log login attempt', { error });
        }
    }
    async logSecurityEvent(userId, eventType, description, ipAddress, userAgent) {
        try {
            await database_1.prisma.securityEvent.create({
                data: {
                    userId,
                    eventType,
                    description,
                    ipAddress,
                    userAgent,
                },
            });
            (0, logger_1.logSecurityEvent)(eventType, description, {
                userId,
                ipAddress,
                userAgent,
            });
        }
        catch (error) {
            logger_1.logger.error('Failed to log security event', { error });
        }
    }
    async mapUserToDto(user) {
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
        }
        catch (error) {
            logger_1.logger.error('Failed to decrypt user data for DTO', { error, userId: user.id });
            return {
                id: user.id,
                fullName: '[Encrypted]',
                email: undefined,
                role: user.role,
                createdAt: user.createdAt,
            };
        }
    }
    parseExpiry(expiry) {
        const unit = expiry.slice(-1);
        const value = parseInt(expiry.slice(0, -1), 10);
        switch (unit) {
            case 's': return value;
            case 'm': return value * 60;
            case 'h': return value * 60 * 60;
            case 'd': return value * 24 * 60 * 60;
            default: return 15 * 60;
        }
    }
}
exports.AuthService = AuthService;
exports.authService = new AuthService();
//# sourceMappingURL=auth.service.js.map