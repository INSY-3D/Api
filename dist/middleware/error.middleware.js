"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.asyncHandler = exports.ExternalServiceError = exports.DatabaseError = exports.RateLimitError = exports.ConflictError = exports.NotFoundError = exports.AuthorizationError = exports.AuthenticationError = exports.ValidationError = exports.notFoundHandler = exports.errorHandler = void 0;
const logger_1 = require("../config/logger");
const logger_2 = require("../config/logger");
const enums_1 = require("../types/enums");
const errorHandler = (error, req, res, next) => {
    logger_1.logger.error('API Error', {
        error: error.message,
        stack: error.stack,
        statusCode: error.statusCode || 500,
        code: error.code,
        path: req.path,
        method: req.method,
        ip: req.ip,
        userAgent: req.get('User-Agent'),
    });
    if (error.statusCode === 401 || error.statusCode === 403) {
        (0, logger_2.logSecurityEvent)(enums_1.EventType.SECURITY_VIOLATION, `Security error: ${error.message}`, {
            ipAddress: req.ip,
            userAgent: req.get('User-Agent'),
            path: req.path,
            method: req.method,
            statusCode: error.statusCode,
            riskLevel: enums_1.SecurityRiskLevel.MEDIUM,
        });
    }
    const statusCode = error.statusCode || 500;
    const errorResponse = {
        success: false,
        message: error.message || 'Internal server error',
        code: error.code || 'INTERNAL_ERROR',
    };
    if (process.env.NODE_ENV === 'development') {
        errorResponse.details = error.details;
        errorResponse.stack = error.stack;
    }
    res.status(statusCode).json(errorResponse);
};
exports.errorHandler = errorHandler;
const notFoundHandler = (req, res, next) => {
    const error = new Error(`Route not found: ${req.method} ${req.path}`);
    error.statusCode = 404;
    error.code = 'ROUTE_NOT_FOUND';
    logger_1.logger.warn('Route not found', {
        method: req.method,
        path: req.path,
        ip: req.ip,
        userAgent: req.get('User-Agent'),
    });
    res.status(404).json({
        success: false,
        message: 'Route not found',
        code: 'ROUTE_NOT_FOUND',
    });
};
exports.notFoundHandler = notFoundHandler;
class ValidationError extends Error {
    statusCode = 400;
    code = 'VALIDATION_ERROR';
    details;
    constructor(message, details) {
        super(message);
        this.name = 'ValidationError';
        this.details = details;
    }
}
exports.ValidationError = ValidationError;
class AuthenticationError extends Error {
    statusCode = 401;
    code = 'AUTHENTICATION_ERROR';
    constructor(message = 'Authentication required') {
        super(message);
        this.name = 'AuthenticationError';
    }
}
exports.AuthenticationError = AuthenticationError;
class AuthorizationError extends Error {
    statusCode = 403;
    code = 'AUTHORIZATION_ERROR';
    constructor(message = 'Insufficient permissions') {
        super(message);
        this.name = 'AuthorizationError';
    }
}
exports.AuthorizationError = AuthorizationError;
class NotFoundError extends Error {
    statusCode = 404;
    code = 'NOT_FOUND';
    constructor(message = 'Resource not found') {
        super(message);
        this.name = 'NotFoundError';
    }
}
exports.NotFoundError = NotFoundError;
class ConflictError extends Error {
    statusCode = 409;
    code = 'CONFLICT';
    constructor(message = 'Resource conflict') {
        super(message);
        this.name = 'ConflictError';
    }
}
exports.ConflictError = ConflictError;
class RateLimitError extends Error {
    statusCode = 429;
    code = 'RATE_LIMIT_EXCEEDED';
    constructor(message = 'Rate limit exceeded') {
        super(message);
        this.name = 'RateLimitError';
    }
}
exports.RateLimitError = RateLimitError;
class DatabaseError extends Error {
    statusCode = 500;
    code = 'DATABASE_ERROR';
    constructor(message = 'Database operation failed') {
        super(message);
        this.name = 'DatabaseError';
    }
}
exports.DatabaseError = DatabaseError;
class ExternalServiceError extends Error {
    statusCode = 502;
    code = 'EXTERNAL_SERVICE_ERROR';
    constructor(message = 'External service error') {
        super(message);
        this.name = 'ExternalServiceError';
    }
}
exports.ExternalServiceError = ExternalServiceError;
const asyncHandler = (fn) => {
    return (req, res, next) => {
        Promise.resolve(fn(req, res, next)).catch(next);
    };
};
exports.asyncHandler = asyncHandler;
//# sourceMappingURL=error.middleware.js.map