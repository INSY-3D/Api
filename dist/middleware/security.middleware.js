"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.corsOptions = exports.requestSizeLimit = exports.ipWhitelist = exports.requestLogging = exports.securityHeaders = exports.wafRateLimit = exports.registerRateLimit = exports.loginRateLimit = exports.apiRateLimit = exports.createRateLimit = exports.wafMiddleware = void 0;
const express_rate_limit_1 = __importDefault(require("express-rate-limit"));
const helmet_1 = __importDefault(require("helmet"));
const config_1 = require("../config");
const logger_1 = require("../config/logger");
const enums_1 = require("../types/enums");
const WAF_RULES = [
    {
        name: 'SQL_INJECTION',
        pattern: /(\b(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|EXEC|UNION|SCRIPT)\b)|(\b(OR|AND)\s+\d+\s*=\s*\d+)|(\b(OR|AND)\s+['"]\s*=\s*['"])/i,
        severity: 'High',
        enabled: config_1.config.waf.enableSqlInjectionDetection,
    },
    {
        name: 'XSS_ATTACK',
        pattern: /<script[^>]*>.*?<\/script>|<[^>]*on\w+\s*=|javascript:|vbscript:|data:text\/html/i,
        severity: 'High',
        enabled: config_1.config.waf.enableXssDetection,
    },
    {
        name: 'PATH_TRAVERSAL',
        pattern: /\.\.\/|\.\.\\|%2e%2e%2f|%2e%2e%5c|\.\.%2f|\.\.%5c/i,
        severity: 'Medium',
        enabled: config_1.config.waf.enablePathTraversalDetection,
    },
    {
        name: 'COMMAND_INJECTION',
        pattern: /[;&|`$(){}[\]\\]/,
        severity: 'High',
        enabled: false,
    },
    {
        name: 'LDAP_INJECTION',
        pattern: /[()=*!&|]/,
        severity: 'Medium',
        enabled: false,
    },
    {
        name: 'NO_SQL_INJECTION',
        pattern: /\$where|\$ne|\$gt|\$lt|\$regex|\$exists|\$in|\$nin/i,
        severity: 'High',
        enabled: true,
    },
];
const wafMiddleware = (req, res, next) => {
    try {
        const contentLength = parseInt(req.get('content-length') || '0', 10);
        if (contentLength > config_1.config.waf.maxRequestSizeBytes) {
            (0, logger_1.logSecurityEvent)(enums_1.EventType.WAF_BLOCKED, 'Request size exceeded limit', {
                ipAddress: req.ip,
                userAgent: req.get('User-Agent'),
                contentLength,
                maxSize: config_1.config.waf.maxRequestSizeBytes,
                riskLevel: enums_1.SecurityRiskLevel.MEDIUM,
            });
            res.status(413).json({
                success: false,
                message: 'Request too large',
                code: 'REQUEST_TOO_LARGE',
            });
            return;
        }
        const url = req.url;
        const wafResult = checkWafRules(url, 'URL');
        if (wafResult.blocked) {
            (0, logger_1.logSecurityEvent)(enums_1.EventType.WAF_BLOCKED, `WAF blocked request: ${wafResult.message}`, {
                ipAddress: req.ip,
                userAgent: req.get('User-Agent'),
                rule: wafResult.rule,
                severity: wafResult.severity,
                url,
                riskLevel: enums_1.SecurityRiskLevel.HIGH,
            });
            res.status(403).json({
                success: false,
                message: 'Request blocked by security policy',
                code: 'WAF_BLOCKED',
            });
            return;
        }
        if (req.body && typeof req.body === 'object') {
            const bodyString = JSON.stringify(req.body);
            const bodyWafResult = checkWafRules(bodyString, 'BODY');
            if (bodyWafResult.blocked) {
                (0, logger_1.logSecurityEvent)(enums_1.EventType.WAF_BLOCKED, `WAF blocked request body: ${bodyWafResult.message}`, {
                    ipAddress: req.ip,
                    userAgent: req.get('User-Agent'),
                    rule: bodyWafResult.rule,
                    severity: bodyWafResult.severity,
                    riskLevel: enums_1.SecurityRiskLevel.HIGH,
                });
                res.status(403).json({
                    success: false,
                    message: 'Request blocked by security policy',
                    code: 'WAF_BLOCKED',
                });
                return;
            }
        }
        const headersString = JSON.stringify(req.headers);
        const headersWafResult = checkWafRules(headersString, 'HEADERS');
        if (headersWafResult.blocked) {
            (0, logger_1.logSecurityEvent)(enums_1.EventType.WAF_BLOCKED, `WAF blocked request headers: ${headersWafResult.message}`, {
                ipAddress: req.ip,
                userAgent: req.get('User-Agent'),
                rule: headersWafResult.rule,
                severity: headersWafResult.severity,
                riskLevel: enums_1.SecurityRiskLevel.HIGH,
            });
            res.status(403).json({
                success: false,
                message: 'Request blocked by security policy',
                code: 'WAF_BLOCKED',
            });
            return;
        }
        next();
    }
    catch (error) {
        logger_1.logger.error('WAF middleware error', { error });
        next();
    }
};
exports.wafMiddleware = wafMiddleware;
function checkWafRules(input, source) {
    for (const rule of WAF_RULES) {
        if (!rule.enabled)
            continue;
        if (rule.pattern.test(input)) {
            return {
                blocked: true,
                rule: rule.name,
                severity: rule.severity,
                message: `Potential ${rule.name.toLowerCase().replace(/_/g, ' ')} detected in ${source}`,
            };
        }
    }
    return {
        blocked: false,
        message: 'Request passed WAF checks',
    };
}
const createRateLimit = (options) => {
    return (0, express_rate_limit_1.default)({
        windowMs: options.windowMs,
        max: options.max,
        message: {
            success: false,
            message: options.message || 'Too many requests, please try again later',
            code: 'RATE_LIMIT_EXCEEDED',
        },
        standardHeaders: true,
        legacyHeaders: false,
        skipSuccessfulRequests: options.skipSuccessfulRequests || false,
        skipFailedRequests: options.skipFailedRequests || false,
        handler: (req, res) => {
            (0, logger_1.logSecurityEvent)(enums_1.EventType.RATE_LIMIT_EXCEEDED, 'Rate limit exceeded', {
                ipAddress: req.ip,
                userAgent: req.get('User-Agent'),
                path: req.path,
                method: req.method,
                riskLevel: enums_1.SecurityRiskLevel.MEDIUM,
            });
            res.status(429).json({
                success: false,
                message: options.message || 'Too many requests, please try again later',
                code: 'RATE_LIMIT_EXCEEDED',
            });
        },
    });
};
exports.createRateLimit = createRateLimit;
exports.apiRateLimit = (0, exports.createRateLimit)({
    windowMs: config_1.config.security.rateLimitWindowMs,
    max: config_1.config.security.rateLimitMaxRequests,
    message: 'Too many API requests, please try again later',
});
exports.loginRateLimit = (0, exports.createRateLimit)({
    windowMs: config_1.config.security.rateLimitLoginWindowMs,
    max: config_1.config.security.rateLimitLoginMax,
    message: 'Too many login attempts, please try again later',
    skipSuccessfulRequests: true,
});
exports.registerRateLimit = (0, exports.createRateLimit)({
    windowMs: config_1.config.security.rateLimitRegisterWindowMs,
    max: config_1.config.security.rateLimitRegisterMax,
    message: 'Too many registration attempts, please try again later',
    skipSuccessfulRequests: true,
});
exports.wafRateLimit = (0, exports.createRateLimit)({
    windowMs: config_1.config.waf.rateLimitWindowMinutes * 60 * 1000,
    max: config_1.config.waf.rateLimitMaxRequests,
    message: 'Too many requests, please try again later',
});
exports.securityHeaders = (0, helmet_1.default)({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            styleSrc: ["'self'", "'unsafe-inline'"],
            scriptSrc: ["'self'"],
            imgSrc: ["'self'", "data:", "https:"],
            connectSrc: ["'self'"],
            fontSrc: ["'self'"],
            objectSrc: ["'none'"],
            mediaSrc: ["'self'"],
            frameSrc: ["'none'"],
            frameAncestors: ["'none'"],
            formAction: ["'self'"],
            baseUri: ["'self'"],
            manifestSrc: ["'self'"],
        },
    },
    crossOriginEmbedderPolicy: false,
    hsts: {
        maxAge: 31536000,
        includeSubDomains: true,
        preload: true,
    },
    noSniff: true,
    xssFilter: true,
    referrerPolicy: { policy: 'strict-origin-when-cross-origin' },
    frameguard: { action: 'deny' },
    dnsPrefetchControl: { allow: false },
    ieNoOpen: true,
    permittedCrossDomainPolicies: false,
});
const requestLogging = (req, res, next) => {
    const startTime = Date.now();
    res.on('finish', () => {
        const duration = Date.now() - startTime;
        logger_1.logger.info('HTTP Request', {
            method: req.method,
            url: req.url,
            statusCode: res.statusCode,
            duration,
            ip: req.ip,
            userAgent: req.get('User-Agent'),
            contentLength: req.get('content-length'),
        });
    });
    next();
};
exports.requestLogging = requestLogging;
const ipWhitelist = (allowedIPs) => {
    return (req, res, next) => {
        const clientIP = req.ip;
        if (allowedIPs.length > 0 && clientIP && !allowedIPs.includes(clientIP)) {
            (0, logger_1.logSecurityEvent)(enums_1.EventType.SECURITY_VIOLATION, 'IP not in whitelist', {
                ipAddress: clientIP,
                userAgent: req.get('User-Agent'),
                path: req.path,
                method: req.method,
                riskLevel: enums_1.SecurityRiskLevel.HIGH,
            });
            res.status(403).json({
                success: false,
                message: 'Access denied',
                code: 'IP_NOT_ALLOWED',
            });
            return;
        }
        next();
    };
};
exports.ipWhitelist = ipWhitelist;
const requestSizeLimit = (maxSize) => {
    return (req, res, next) => {
        const contentLength = parseInt(req.get('content-length') || '0', 10);
        if (contentLength > maxSize) {
            (0, logger_1.logSecurityEvent)(enums_1.EventType.SECURITY_VIOLATION, 'Request size exceeded', {
                ipAddress: req.ip,
                userAgent: req.get('User-Agent'),
                contentLength,
                maxSize,
                riskLevel: enums_1.SecurityRiskLevel.MEDIUM,
            });
            res.status(413).json({
                success: false,
                message: 'Request too large',
                code: 'REQUEST_TOO_LARGE',
            });
            return;
        }
        next();
    };
};
exports.requestSizeLimit = requestSizeLimit;
exports.corsOptions = {
    origin: (origin, callback) => {
        if (!origin)
            return callback(null, true);
        if (config_1.config.cors.origins.includes(origin)) {
            callback(null, true);
        }
        else {
            (0, logger_1.logSecurityEvent)(enums_1.EventType.SECURITY_VIOLATION, 'CORS origin not allowed', {
                origin,
                riskLevel: enums_1.SecurityRiskLevel.MEDIUM,
            });
            callback(new Error('Not allowed by CORS'), false);
        }
    },
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'X-CSRF-Token'],
    exposedHeaders: ['X-RateLimit-Limit', 'X-RateLimit-Remaining', 'X-RateLimit-Reset'],
    maxAge: 86400,
};
//# sourceMappingURL=security.middleware.js.map