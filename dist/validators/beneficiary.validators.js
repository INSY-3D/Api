"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.createBeneficiarySchema = void 0;
const zod_1 = require("zod");
exports.createBeneficiarySchema = zod_1.z.object({
    fullName: zod_1.z.string()
        .min(2, 'Full name must be at least 2 characters')
        .max(100, 'Full name must not exceed 100 characters')
        .regex(/^[a-zA-Z\s\-'\.]+$/, 'Full name contains invalid characters'),
    bankName: zod_1.z.string()
        .min(2, 'Bank name must be at least 2 characters')
        .max(100, 'Bank name must not exceed 100 characters')
        .regex(/^[a-zA-Z0-9\s\-'\.&]+$/, 'Bank name contains invalid characters'),
    accountNumber: zod_1.z.string()
        .min(8, 'Account number must be at least 8 characters')
        .max(34, 'Account number must not exceed 34 characters')
        .regex(/^[a-zA-Z0-9]+$/, 'Account number must contain only alphanumeric characters'),
    swiftCode: zod_1.z.string()
        .min(8, 'SWIFT code must be at least 8 characters')
        .max(11, 'SWIFT code must not exceed 11 characters')
        .regex(/^[A-Za-z0-9]{8}([A-Za-z0-9]{3})?$/, 'Invalid SWIFT code format'),
});
//# sourceMappingURL=beneficiary.validators.js.map