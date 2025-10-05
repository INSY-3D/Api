import { z } from 'zod';
export declare const createPaymentSchema: z.ZodObject<{
    amount: z.ZodString;
    currency: z.ZodString;
    provider: z.ZodDefault<z.ZodString>;
    idempotencyKey: z.ZodString;
    reference: z.ZodOptional<z.ZodString>;
    purpose: z.ZodOptional<z.ZodString>;
}, "strip", z.ZodTypeAny, {
    idempotencyKey: string;
    amount: string;
    currency: string;
    provider: string;
    reference?: string | undefined;
    purpose?: string | undefined;
}, {
    idempotencyKey: string;
    amount: string;
    currency: string;
    provider?: string | undefined;
    reference?: string | undefined;
    purpose?: string | undefined;
}>;
export declare const updateBeneficiarySchema: z.ZodObject<{
    beneficiaryName: z.ZodString;
    beneficiaryAccountNumber: z.ZodString;
    swiftBic: z.ZodString;
    beneficiaryIban: z.ZodEffects<z.ZodOptional<z.ZodString>, string | undefined, string | undefined>;
    beneficiaryAddress: z.ZodString;
    beneficiaryCity: z.ZodString;
    beneficiaryPostalCode: z.ZodString;
    beneficiaryCountry: z.ZodString;
}, "strip", z.ZodTypeAny, {
    beneficiaryName: string;
    beneficiaryAccountNumber: string;
    swiftBic: string;
    beneficiaryAddress: string;
    beneficiaryCity: string;
    beneficiaryPostalCode: string;
    beneficiaryCountry: string;
    beneficiaryIban?: string | undefined;
}, {
    beneficiaryName: string;
    beneficiaryAccountNumber: string;
    swiftBic: string;
    beneficiaryAddress: string;
    beneficiaryCity: string;
    beneficiaryPostalCode: string;
    beneficiaryCountry: string;
    beneficiaryIban?: string | undefined;
}>;
export declare const submitPaymentSchema: z.ZodObject<{
    reference: z.ZodOptional<z.ZodString>;
    purpose: z.ZodOptional<z.ZodString>;
    otp: z.ZodOptional<z.ZodString>;
}, "strip", z.ZodTypeAny, {
    otp?: string | undefined;
    reference?: string | undefined;
    purpose?: string | undefined;
}, {
    otp?: string | undefined;
    reference?: string | undefined;
    purpose?: string | undefined;
}>;
export declare const verifyPaymentSchema: z.ZodObject<{
    action: z.ZodEnum<["approve", "reject"]>;
    notes: z.ZodOptional<z.ZodString>;
}, "strip", z.ZodTypeAny, {
    action: "approve" | "reject";
    notes?: string | undefined;
}, {
    action: "approve" | "reject";
    notes?: string | undefined;
}>;
export type CreatePaymentRequest = z.infer<typeof createPaymentSchema>;
export type UpdateBeneficiaryRequest = z.infer<typeof updateBeneficiarySchema>;
export type SubmitPaymentRequest = z.infer<typeof submitPaymentSchema>;
export type VerifyPaymentRequest = z.infer<typeof verifyPaymentSchema>;
//# sourceMappingURL=payment.validators.d.ts.map