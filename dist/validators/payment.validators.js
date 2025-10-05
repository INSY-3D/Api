"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.verifyPaymentSchema = exports.submitPaymentSchema = exports.updateBeneficiarySchema = exports.createPaymentSchema = void 0;
const zod_1 = require("zod");
const validation_1 = require("@/types/validation");
exports.createPaymentSchema = zod_1.z.object({
    amount: zod_1.z.string()
        .min(1, 'Amount is required')
        .regex(validation_1.VALIDATION_PATTERNS.amount, 'Invalid amount format'),
    currency: zod_1.z.string()
        .length(3, 'Currency must be exactly 3 characters')
        .regex(validation_1.VALIDATION_PATTERNS.currency, 'Invalid currency format'),
    provider: zod_1.z.string()
        .min(1, 'Provider is required')
        .max(20, 'Provider must not exceed 20 characters')
        .default('SWIFT'),
    idempotencyKey: zod_1.z.string()
        .min(1, 'Idempotency key is required')
        .max(50, 'Idempotency key must not exceed 50 characters'),
    reference: zod_1.z.string()
        .min(1, 'Reference is required')
        .max(35, 'Reference must not exceed 35 characters')
        .optional(),
    purpose: zod_1.z.string()
        .min(1, 'Purpose is required')
        .max(140, 'Purpose must not exceed 140 characters')
        .optional(),
});
exports.updateBeneficiarySchema = zod_1.z.object({
    beneficiaryName: zod_1.z.string()
        .min(1, 'Beneficiary name is required')
        .max(100, 'Beneficiary name must not exceed 100 characters'),
    beneficiaryAccountNumber: zod_1.z.string()
        .min(1, 'Beneficiary account number is required')
        .max(18, 'Beneficiary account number must not exceed 18 characters'),
    swiftBic: zod_1.z.string()
        .min(8, 'SWIFT/BIC code must be at least 8 characters')
        .max(11, 'SWIFT/BIC code must not exceed 11 characters')
        .regex(/^[A-Za-z0-9]{8}([A-Za-z0-9]{3})?$/, 'Invalid SWIFT/BIC code format'),
    beneficiaryIban: zod_1.z.string()
        .max(34, 'IBAN must not exceed 34 characters')
        .optional()
        .refine((val) => !val || validation_1.VALIDATION_PATTERNS.iban.test(val), {
        message: 'Invalid IBAN format'
    }),
    beneficiaryAddress: zod_1.z.string()
        .min(1, 'Beneficiary address is required')
        .max(70, 'Beneficiary address must not exceed 70 characters'),
    beneficiaryCity: zod_1.z.string()
        .min(1, 'Beneficiary city is required')
        .max(35, 'Beneficiary city must not exceed 35 characters'),
    beneficiaryPostalCode: zod_1.z.string()
        .min(1, 'Beneficiary postal code is required')
        .max(16, 'Beneficiary postal code must not exceed 16 characters'),
    beneficiaryCountry: zod_1.z.string()
        .length(2, 'Beneficiary country must be exactly 2 characters')
        .regex(/^[A-Z]{2}$/, 'Invalid country code format'),
});
exports.submitPaymentSchema = zod_1.z.object({
    reference: zod_1.z.string()
        .min(1, 'Reference is required')
        .max(35, 'Reference must not exceed 35 characters')
        .optional(),
    purpose: zod_1.z.string()
        .min(1, 'Purpose is required')
        .max(140, 'Purpose must not exceed 140 characters')
        .optional(),
    otp: zod_1.z.string()
        .optional(),
});
exports.verifyPaymentSchema = zod_1.z.object({
    action: zod_1.z.enum(['approve', 'reject'], {
        errorMap: () => ({ message: 'Action must be either approve or reject' })
    }),
    notes: zod_1.z.string()
        .max(500, 'Notes must not exceed 500 characters')
        .optional(),
});
//# sourceMappingURL=payment.validators.js.map