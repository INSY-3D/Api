export declare class OtpService {
    private readonly OTP_LENGTH;
    private readonly OTP_EXPIRY_MINUTES;
    private readonly MAX_ATTEMPTS;
    private generateOtpCode;
    generateAndSendOtp(email: string, userId?: string, purpose?: string): Promise<{
        success: boolean;
        message: string;
        otpId?: string;
    }>;
    verifyOtp(email: string, code: string, purpose?: string): Promise<{
        valid: boolean;
        message: string;
        userId?: string;
    }>;
    cleanupExpiredOtps(): Promise<number>;
    private maskEmail;
}
export declare const otpService: OtpService;
//# sourceMappingURL=otp.service.d.ts.map