export declare class EmailService {
    private isDevelopment;
    private transporter;
    private useRealEmail;
    constructor();
    private initializeTransporter;
    sendOtpEmail(email: string, code: string, expiresInMinutes?: number): Promise<boolean>;
    private sendEmailViaSMTP;
    private getOtpEmailTemplate;
    private maskEmail;
}
export declare const emailService: EmailService;
//# sourceMappingURL=email.service.d.ts.map