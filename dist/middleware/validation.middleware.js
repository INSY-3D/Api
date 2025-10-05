"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.sanitizeRequest = exports.validateParams = exports.validateQuery = exports.validateRequest = void 0;
const zod_1 = require("zod");
const logger_1 = require("@/config/logger");
const validateRequest = (schema) => {
    return (req, res, next) => {
        try {
            const validatedData = schema.parse(req.body);
            req.body = validatedData;
            next();
        }
        catch (error) {
            if (error instanceof zod_1.z.ZodError) {
                const errors = error.errors.map(err => ({
                    field: err.path.join('.'),
                    message: err.message,
                    value: err.input,
                }));
                logger_1.logger.warn('Request validation failed', {
                    errors,
                    path: req.path,
                    method: req.method,
                    ip: req.ip,
                });
                res.status(400).json({
                    success: false,
                    message: 'Validation failed',
                    code: 'VALIDATION_FAILED',
                    errors: errors.map(err => err.message),
                });
                return;
            }
            logger_1.logger.error('Validation middleware error', { error });
            res.status(500).json({
                success: false,
                message: 'Internal server error',
                code: 'INTERNAL_ERROR',
            });
        }
    };
};
exports.validateRequest = validateRequest;
const validateQuery = (schema) => {
    return (req, res, next) => {
        try {
            const validatedData = schema.parse(req.query);
            req.query = validatedData;
            next();
        }
        catch (error) {
            if (error instanceof zod_1.z.ZodError) {
                const errors = error.errors.map(err => ({
                    field: err.path.join('.'),
                    message: err.message,
                    value: err.input,
                }));
                logger_1.logger.warn('Query validation failed', {
                    errors,
                    path: req.path,
                    method: req.method,
                    ip: req.ip,
                });
                res.status(400).json({
                    success: false,
                    message: 'Query validation failed',
                    code: 'QUERY_VALIDATION_FAILED',
                    errors: errors.map(err => err.message),
                });
                return;
            }
            logger_1.logger.error('Query validation middleware error', { error });
            res.status(500).json({
                success: false,
                message: 'Internal server error',
                code: 'INTERNAL_ERROR',
            });
        }
    };
};
exports.validateQuery = validateQuery;
const validateParams = (schema) => {
    return (req, res, next) => {
        try {
            const validatedData = schema.parse(req.params);
            req.params = validatedData;
            next();
        }
        catch (error) {
            if (error instanceof zod_1.z.ZodError) {
                const errors = error.errors.map(err => ({
                    field: err.path.join('.'),
                    message: err.message,
                    value: err.input,
                }));
                logger_1.logger.warn('Params validation failed', {
                    errors,
                    path: req.path,
                    method: req.method,
                    ip: req.ip,
                });
                res.status(400).json({
                    success: false,
                    message: 'Path parameter validation failed',
                    code: 'PARAMS_VALIDATION_FAILED',
                    errors: errors.map(err => err.message),
                });
                return;
            }
            logger_1.logger.error('Params validation middleware error', { error });
            res.status(500).json({
                success: false,
                message: 'Internal server error',
                code: 'INTERNAL_ERROR',
            });
        }
    };
};
exports.validateParams = validateParams;
const sanitizeRequest = (req, res, next) => {
    try {
        if (req.body && typeof req.body === 'object') {
            req.body = sanitizeObject(req.body);
        }
        next();
    }
    catch (error) {
        logger_1.logger.error('Request sanitization error', { error });
        next();
    }
};
exports.sanitizeRequest = sanitizeRequest;
function sanitizeObject(obj) {
    if (typeof obj !== 'object' || obj === null) {
        return obj;
    }
    if (Array.isArray(obj)) {
        return obj.map(sanitizeObject);
    }
    const sanitized = {};
    for (const [key, value] of Object.entries(obj)) {
        if (typeof value === 'string') {
            sanitized[key] = value.replace(/[\x00-\x1F\x7F]/g, '').trim();
        }
        else if (typeof value === 'object' && value !== null) {
            sanitized[key] = sanitizeObject(value);
        }
        else {
            sanitized[key] = value;
        }
    }
    return sanitized;
}
//# sourceMappingURL=validation.middleware.js.map