import { z } from 'zod';
export declare const createBeneficiarySchema: z.ZodObject<{
    fullName: z.ZodString;
    bankName: z.ZodString;
    accountNumber: z.ZodString;
    swiftCode: z.ZodString;
}, "strip", z.ZodTypeAny, {
    fullName: string;
    accountNumber: string;
    swiftCode: string;
    bankName: string;
}, {
    fullName: string;
    accountNumber: string;
    swiftCode: string;
    bankName: string;
}>;
export type CreateBeneficiaryRequest = z.infer<typeof createBeneficiarySchema>;
//# sourceMappingURL=beneficiary.validators.d.ts.map