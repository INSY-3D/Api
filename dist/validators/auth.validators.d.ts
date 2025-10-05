import { z } from 'zod';
export declare const registerSchema: z.ZodObject<{
    fullName: z.ZodString;
    saId: z.ZodString;
    accountNumber: z.ZodString;
    email: z.ZodOptional<z.ZodString>;
    password: z.ZodString;
}, "strip", z.ZodTypeAny, {
    fullName: string;
    saId: string;
    accountNumber: string;
    password: string;
    email?: string | undefined;
}, {
    fullName: string;
    saId: string;
    accountNumber: string;
    password: string;
    email?: string | undefined;
}>;
export declare const loginSchema: z.ZodObject<{
    usernameOrEmail: z.ZodString;
    accountNumber: z.ZodString;
    password: z.ZodString;
    otp: z.ZodOptional<z.ZodString>;
}, "strip", z.ZodTypeAny, {
    accountNumber: string;
    password: string;
    usernameOrEmail: string;
    otp?: string | undefined;
}, {
    accountNumber: string;
    password: string;
    usernameOrEmail: string;
    otp?: string | undefined;
}>;
export declare const refreshTokenSchema: z.ZodObject<{
    refreshToken: z.ZodString;
}, "strip", z.ZodTypeAny, {
    refreshToken: string;
}, {
    refreshToken: string;
}>;
export declare const staffLoginSchema: z.ZodObject<{
    usernameOrEmail: z.ZodString;
    accountNumber: z.ZodString;
    password: z.ZodString;
    otp: z.ZodOptional<z.ZodString>;
}, "strip", z.ZodTypeAny, {
    accountNumber: string;
    password: string;
    usernameOrEmail: string;
    otp?: string | undefined;
}, {
    accountNumber: string;
    password: string;
    usernameOrEmail: string;
    otp?: string | undefined;
}>;
export type RegisterRequest = z.infer<typeof registerSchema>;
export type LoginRequest = z.infer<typeof loginSchema>;
export type RefreshTokenRequest = z.infer<typeof refreshTokenSchema>;
export type StaffLoginRequest = z.infer<typeof staffLoginSchema>;
//# sourceMappingURL=auth.validators.d.ts.map