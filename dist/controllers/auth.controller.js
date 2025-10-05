"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.authController = exports.AuthController = void 0;
const auth_service_1 = require("@/services/auth.service");
const logger_1 = require("@/config/logger");
class AuthController {
    async register(req, res) {
        try {
            const userData = req.body;
            const ipAddress = this.getClientIpAddress(req);
            const userAgent = req.get('User-Agent') || '';
            logger_1.logger.info('User registration attempt', {
                ipAddress,
                userAgent,
                fullName: userData.fullName,
            });
            const result = await auth_service_1.authService.register(userData, ipAddress, userAgent);
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
        }
        catch (error) {
            logger_1.logger.error('Registration failed', { error });
            res.status(400).json({
                success: false,
                message: error instanceof Error ? error.message : 'Registration failed',
                code: 'REGISTRATION_FAILED',
            });
        }
    }
    async login(req, res) {
        try {
            const loginData = req.body;
            const ipAddress = this.getClientIpAddress(req);
            const userAgent = req.get('User-Agent') || '';
            logger_1.logger.info('User login attempt', {
                ipAddress,
                userAgent,
                usernameOrEmail: loginData.usernameOrEmail,
            });
            const result = await auth_service_1.authService.login(loginData, ipAddress, userAgent);
            if (result.mfa === 'required') {
                res.status(200).json({
                    success: true,
                    message: 'MFA required',
                    data: {
                        mfa: 'required',
                        user: result.user,
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
        }
        catch (error) {
            logger_1.logger.error('Login failed', { error });
            res.status(401).json({
                success: false,
                message: error instanceof Error ? error.message : 'Login failed',
                code: 'LOGIN_FAILED',
            });
        }
    }
    async logout(req, res) {
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
            await auth_service_1.authService.logout(userId, sessionId);
            res.status(200).json({
                success: true,
                message: 'Logout successful',
            });
        }
        catch (error) {
            logger_1.logger.error('Logout failed', { error });
            res.status(500).json({
                success: false,
                message: 'Logout failed',
                code: 'LOGOUT_FAILED',
            });
        }
    }
    async getMe(req, res) {
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
                        fullName: req.user.fullNameEncrypted,
                        email: req.user.emailEncrypted,
                        role: req.user.role,
                        createdAt: req.user.createdAt,
                    },
                },
            });
        }
        catch (error) {
            logger_1.logger.error('Get user info failed', { error });
            res.status(500).json({
                success: false,
                message: 'Failed to get user information',
                code: 'USER_INFO_FAILED',
            });
        }
    }
    async refreshToken(req, res) {
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
            const isValid = auth_service_1.authService.verifyRefreshToken(refreshToken);
            if (!isValid) {
                res.status(401).json({
                    success: false,
                    message: 'Invalid refresh token',
                    code: 'INVALID_REFRESH_TOKEN',
                });
                return;
            }
            res.status(200).json({
                success: true,
                message: 'Token refreshed successfully',
                data: {
                    accessToken: 'new-access-token',
                    expiresIn: '15m',
                },
            });
        }
        catch (error) {
            logger_1.logger.error('Token refresh failed', { error });
            res.status(500).json({
                success: false,
                message: 'Token refresh failed',
                code: 'REFRESH_FAILED',
            });
        }
    }
    async getCsrfToken(req, res) {
        try {
            const csrfToken = this.generateCsrfToken();
            const ipAddress = this.getClientIpAddress(req);
            res.status(200).json({
                success: true,
                data: {
                    token: csrfToken,
                },
            });
        }
        catch (error) {
            logger_1.logger.error('CSRF token generation failed', { error });
            res.status(500).json({
                success: false,
                message: 'Failed to generate CSRF token',
                code: 'CSRF_GENERATION_FAILED',
            });
        }
    }
    async staffLogin(req, res) {
        try {
            const loginData = req.body;
            const ipAddress = this.getClientIpAddress(req);
            const userAgent = req.get('User-Agent') || '';
            logger_1.logger.info('Staff login attempt', {
                ipAddress,
                userAgent,
                usernameOrEmail: loginData.usernameOrEmail,
            });
            const result = await auth_service_1.authService.login(loginData, ipAddress, userAgent);
            if (result.user.role !== 'staff' && result.user.role !== 'admin') {
                res.status(403).json({
                    success: false,
                    message: 'Staff access required',
                    code: 'STAFF_ACCESS_REQUIRED',
                });
                return;
            }
            if (result.mfa === 'required') {
                res.status(200).json({
                    success: true,
                    message: 'MFA required',
                    data: {
                        mfa: 'required',
                        user: result.user,
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
        }
        catch (error) {
            logger_1.logger.error('Staff login failed', { error });
            res.status(401).json({
                success: false,
                message: error instanceof Error ? error.message : 'Staff login failed',
                code: 'STAFF_LOGIN_FAILED',
            });
        }
    }
    getClientIpAddress(req) {
        return (req.headers['x-forwarded-for'] ||
            req.headers['x-real-ip'] ||
            req.connection.remoteAddress ||
            req.socket.remoteAddress ||
            'unknown');
    }
    generateCsrfToken() {
        const crypto = require('crypto');
        return crypto.randomBytes(32).toString('hex');
    }
}
exports.AuthController = AuthController;
exports.authController = new AuthController();
//# sourceMappingURL=auth.controller.js.map