"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.staffLoginSchema = exports.refreshTokenSchema = exports.loginSchema = exports.registerSchema = void 0;
const zod_1 = require("zod");
const validation_1 = require("@/types/validation");
exports.registerSchema = zod_1.z.object({
    fullName: zod_1.z.string()
        .min(2, 'Full name must be at least 2 characters')
        .max(100, 'Full name must not exceed 100 characters')
        .regex(validation_1.VALIDATION_PATTERNS.fullName, 'Invalid full name format'),
    saId: zod_1.z.string()
        .length(13, 'South African ID must be exactly 13 digits')
        .regex(validation_1.VALIDATION_PATTERNS.saId, 'Invalid SA ID format'),
    accountNumber: zod_1.z.string()
        .min(8, 'Account number must be at least 8 digits')
        .max(12, 'Account number must not exceed 12 digits')
        .regex(validation_1.VALIDATION_PATTERNS.accountNumber, 'Invalid account number format'),
    email: zod_1.z.string()
        .email('Invalid email format')
        .optional(),
    password: zod_1.z.string()
        .min(8, 'Password must be at least 8 characters')
        .regex(validation_1.VALIDATION_PATTERNS.password, 'Password must contain uppercase, lowercase, number, and special character'),
});
exports.loginSchema = zod_1.z.object({
    usernameOrEmail: zod_1.z.string()
        .min(1, 'Username or email is required')
        .max(254, 'Username or email must not exceed 254 characters'),
    accountNumber: zod_1.z.string()
        .min(8, 'Account number must be at least 8 digits')
        .max(12, 'Account number must not exceed 12 digits')
        .regex(validation_1.VALIDATION_PATTERNS.accountNumber, 'Invalid account number format'),
    password: zod_1.z.string()
        .min(1, 'Password is required'),
    otp: zod_1.z.string()
        .optional(),
});
exports.refreshTokenSchema = zod_1.z.object({
    refreshToken: zod_1.z.string()
        .min(1, 'Refresh token is required'),
});
exports.staffLoginSchema = zod_1.z.object({
    usernameOrEmail: zod_1.z.string()
        .min(1, 'Username or email is required')
        .max(254, 'Username or email must not exceed 254 characters'),
    accountNumber: zod_1.z.string()
        .min(1, 'Account number is required')
        .max(18, 'Account number must not exceed 18 characters'),
    password: zod_1.z.string()
        .min(1, 'Password is required'),
    otp: zod_1.z.string()
        .optional(),
});
//# sourceMappingURL=auth.validators.js.map