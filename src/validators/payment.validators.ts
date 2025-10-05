import { z } from 'zod';
import { VALIDATION_PATTERNS } from '@/types/validation';

// Task 2 Compliant: Payment validation schemas

export const createPaymentSchema = z.object({
  amount: z.string()
    .min(1, 'Amount is required')
    .regex(VALIDATION_PATTERNS.amount, 'Invalid amount format'),
  
  currency: z.string()
    .length(3, 'Currency must be exactly 3 characters')
    .regex(VALIDATION_PATTERNS.currency, 'Invalid currency format'),
  
  provider: z.string()
    .min(1, 'Provider is required')
    .max(20, 'Provider must not exceed 20 characters')
    .default('SWIFT'),
  
  idempotencyKey: z.string()
    .min(1, 'Idempotency key is required')
    .max(50, 'Idempotency key must not exceed 50 characters'),
  
  reference: z.string()
    .min(1, 'Reference is required')
    .max(35, 'Reference must not exceed 35 characters')
    .optional(),
  
  purpose: z.string()
    .min(1, 'Purpose is required')
    .max(140, 'Purpose must not exceed 140 characters')
    .optional(),
});

export const updateBeneficiarySchema = z.object({
  beneficiaryName: z.string()
    .min(1, 'Beneficiary name is required')
    .max(100, 'Beneficiary name must not exceed 100 characters'),
  
  beneficiaryAccountNumber: z.string()
    .min(1, 'Beneficiary account number is required')
    .max(18, 'Beneficiary account number must not exceed 18 characters'),
  
  swiftBic: z.string()
    .min(8, 'SWIFT/BIC code must be at least 8 characters')
    .max(11, 'SWIFT/BIC code must not exceed 11 characters')
    .regex(/^[A-Za-z0-9]{8}([A-Za-z0-9]{3})?$/, 'Invalid SWIFT/BIC code format'),
  
  beneficiaryIban: z.string()
    .max(34, 'IBAN must not exceed 34 characters')
    .optional()
    .refine((val) => !val || VALIDATION_PATTERNS.iban.test(val), {
      message: 'Invalid IBAN format'
    }),
  
  beneficiaryAddress: z.string()
    .min(1, 'Beneficiary address is required')
    .max(70, 'Beneficiary address must not exceed 70 characters'),
  
  beneficiaryCity: z.string()
    .min(1, 'Beneficiary city is required')
    .max(35, 'Beneficiary city must not exceed 35 characters'),
  
  beneficiaryPostalCode: z.string()
    .min(1, 'Beneficiary postal code is required')
    .max(16, 'Beneficiary postal code must not exceed 16 characters'),
  
  beneficiaryCountry: z.string()
    .length(2, 'Beneficiary country must be exactly 2 characters')
    .regex(/^[A-Z]{2}$/, 'Invalid country code format'),
});

export const submitPaymentSchema = z.object({
  reference: z.string()
    .min(1, 'Reference is required')
    .max(35, 'Reference must not exceed 35 characters')
    .optional(),
  
  purpose: z.string()
    .min(1, 'Purpose is required')
    .max(140, 'Purpose must not exceed 140 characters')
    .optional(),
  
  otp: z.string()
    .optional(),
});

export const verifyPaymentSchema = z.object({
  action: z.enum(['approve', 'reject'], {
    errorMap: () => ({ message: 'Action must be either approve or reject' })
  }),
  
  notes: z.string()
    .max(500, 'Notes must not exceed 500 characters')
    .optional(),
});

// Type exports for TypeScript
export type CreatePaymentRequest = z.infer<typeof createPaymentSchema>;
export type UpdateBeneficiaryRequest = z.infer<typeof updateBeneficiarySchema>;
export type SubmitPaymentRequest = z.infer<typeof submitPaymentSchema>;
export type VerifyPaymentRequest = z.infer<typeof verifyPaymentSchema>;
