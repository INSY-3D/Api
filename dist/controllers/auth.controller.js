"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || (function () {
    var ownKeys = function(o) {
        ownKeys = Object.getOwnPropertyNames || function (o) {
            var ar = [];
            for (var k in o) if (Object.prototype.hasOwnProperty.call(o, k)) ar[ar.length] = k;
            return ar;
        };
        return ownKeys(o);
    };
    return function (mod) {
        if (mod && mod.__esModule) return mod;
        var result = {};
        if (mod != null) for (var k = ownKeys(mod), i = 0; i < k.length; i++) if (k[i] !== "default") __createBinding(result, mod, k[i]);
        __setModuleDefault(result, mod);
        return result;
    };
})();
Object.defineProperty(exports, "__esModule", { value: true });
exports.authController = exports.AuthController = void 0;
const auth_service_1 = require("../services/auth.service");
const logger_1 = require("../config/logger");
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
                    message: result.message,
                    data: {
                        mfa: 'required',
                        user: result.user,
                        hasEmail: result.hasEmail,
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
    async sendOtp(req, res) {
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
            logger_1.logger.info('OTP send request', { email, userId, ipAddress });
            const { otpService } = await Promise.resolve().then(() => __importStar(require('../services/otp.service')));
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
        }
        catch (error) {
            logger_1.logger.error('Send OTP failed', { error });
            res.status(500).json({
                success: false,
                message: 'Failed to send OTP',
                code: 'OTP_SEND_FAILED',
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
                    message: result.message,
                    data: {
                        mfa: 'required',
                        user: result.user,
                        hasEmail: result.hasEmail,
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