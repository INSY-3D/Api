"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.csrfProtection = exports.authRateLimit = exports.validateDevice = exports.validateSession = exports.optionalAuth = exports.requireAdmin = exports.requireStaff = exports.requireCustomer = exports.requireRole = exports.authenticateToken = void 0;
const auth_service_1 = require("@/services/auth.service");
const logger_1 = require("@/config/logger");
const enums_1 = require("@/types/enums");
const authenticateToken = async (req, res, next) => {
    try {
        const authHeader = req.headers.authorization;
        const token = authHeader && authHeader.split(' ')[1];
        if (!token) {
            res.status(401).json({
                success: false,
                message: 'Access token required',
                code: 'MISSING_TOKEN',
            });
            return;
        }
        const payload = auth_service_1.authService.verifyAccessToken(token);
        if (!payload) {
            res.status(401).json({
                success: false,
                message: 'Invalid or expired token',
                code: 'INVALID_TOKEN',
            });
            return;
        }
        const user = await auth_service_1.authService.getUserById(payload.userId);
        if (!user || !user.isActive) {
            res.status(401).json({
                success: false,
                message: 'User not found or inactive',
                code: 'USER_NOT_FOUND',
            });
            return;
        }
        const session = await auth_service_1.authService.getUserSession(payload.sessionId);
        if (!session || !session.isActive || session.expiresAt < new Date()) {
            res.status(401).json({
                success: false,
                message: 'Session expired or invalid',
                code: 'SESSION_EXPIRED',
            });
            return;
        }
        req.user = user;
        req.session = session;
        next();
    }
    catch (error) {
        logger_1.logger.error('Authentication middleware error', { error });
        res.status(500).json({
            success: false,
            message: 'Authentication error',
            code: 'AUTH_ERROR',
        });
    }
};
exports.authenticateToken = authenticateToken;
const requireRole = (roles) => {
    return (req, res, next) => {
        if (!req.user) {
            res.status(401).json({
                success: false,
                message: 'Authentication required',
                code: 'AUTH_REQUIRED',
            });
            return;
        }
        if (!roles.includes(req.user.role)) {
            (0, logger_1.logSecurityEvent)(enums_1.EventType.SECURITY_VIOLATION, `Unauthorized access attempt by user ${req.user.id} to role-protected resource`, {
                userId: req.user.id,
                userRole: req.user.role,
                requiredRoles: roles,
                ipAddress: req.ip,
                userAgent: req.get('User-Agent'),
                riskLevel: enums_1.SecurityRiskLevel.HIGH,
            });
            res.status(403).json({
                success: false,
                message: 'Insufficient permissions',
                code: 'INSUFFICIENT_PERMISSIONS',
            });
            return;
        }
        next();
    };
};
exports.requireRole = requireRole;
exports.requireCustomer = (0, exports.requireRole)(['customer']);
exports.requireStaff = (0, exports.requireRole)(['staff', 'admin']);
exports.requireAdmin = (0, exports.requireRole)(['admin']);
const optionalAuth = async (req, res, next) => {
    try {
        const authHeader = req.headers.authorization;
        const token = authHeader && authHeader.split(' ')[1];
        if (!token) {
            next();
            return;
        }
        const payload = auth_service_1.authService.verifyAccessToken(token);
        if (!payload) {
            next();
            return;
        }
        const user = await auth_service_1.authService.getUserById(payload.userId);
        if (!user || !user.isActive) {
            next();
            return;
        }
        const session = await auth_service_1.authService.getUserSession(payload.sessionId);
        if (!session || !session.isActive || session.expiresAt < new Date()) {
            next();
            return;
        }
        req.user = user;
        req.session = session;
        next();
    }
    catch (error) {
        logger_1.logger.error('Optional authentication middleware error', { error });
        next();
    }
};
exports.optionalAuth = optionalAuth;
const validateSession = async (req, res, next) => {
    try {
        if (!req.session) {
            res.status(401).json({
                success: false,
                message: 'Valid session required',
                code: 'SESSION_REQUIRED',
            });
            return;
        }
        if (req.session.expiresAt < new Date()) {
            await auth_service_1.authService.logout(req.user.id, req.session.id);
            res.status(401).json({
                success: false,
                message: 'Session expired',
                code: 'SESSION_EXPIRED',
            });
            return;
        }
        if (!req.session.isActive) {
            res.status(401).json({
                success: false,
                message: 'Session invalidated',
                code: 'SESSION_INVALID',
            });
            return;
        }
        next();
    }
    catch (error) {
        logger_1.logger.error('Session validation middleware error', { error });
        res.status(500).json({
            success: false,
            message: 'Session validation error',
            code: 'SESSION_ERROR',
        });
    }
};
exports.validateSession = validateSession;
const validateDevice = async (req, res, next) => {
    try {
        if (!req.user || !req.session) {
            next();
            return;
        }
        const currentIp = req.ip;
        const currentUserAgent = req.get('User-Agent');
        if (req.session.ipAddress !== currentIp || req.session.userAgent !== currentUserAgent) {
            (0, logger_1.logSecurityEvent)(enums_1.EventType.SUSPICIOUS_ACTIVITY, `Device change detected for user ${req.user.id}`, {
                userId: req.user.id,
                oldIp: req.session.ipAddress,
                newIp: currentIp,
                oldUserAgent: req.session.userAgent,
                newUserAgent: currentUserAgent,
                riskLevel: enums_1.SecurityRiskLevel.MEDIUM,
            });
            req.session.ipAddress = currentIp || null;
            req.session.userAgent = currentUserAgent || null;
        }
        next();
    }
    catch (error) {
        logger_1.logger.error('Device validation middleware error', { error });
        next();
    }
};
exports.validateDevice = validateDevice;
const authRateLimit = (req, res, next) => {
    next();
};
exports.authRateLimit = authRateLimit;
const csrfProtection = (req, res, next) => {
    if (['GET', 'HEAD', 'OPTIONS'].includes(req.method)) {
        next();
        return;
    }
    const csrfToken = req.headers['x-csrf-token'];
    const sessionToken = req.session?.csrfToken;
    if (!csrfToken || !sessionToken || csrfToken !== sessionToken) {
        res.status(403).json({
            success: false,
            message: 'CSRF token mismatch',
            code: 'CSRF_MISMATCH',
        });
        return;
    }
    next();
};
exports.csrfProtection = csrfProtection;
//# sourceMappingURL=auth.middleware.js.map