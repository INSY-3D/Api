"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.otpService = exports.OtpService = void 0;
const database_1 = require("../config/database");
const logger_1 = require("../config/logger");
const email_service_1 = require("./email.service");
const crypto_1 = __importDefault(require("crypto"));
class OtpService {
    OTP_LENGTH = 6;
    OTP_EXPIRY_MINUTES = 10;
    MAX_ATTEMPTS = 3;
    generateOtpCode() {
        const code = crypto_1.default.randomInt(100000, 999999).toString();
        return code;
    }
    async generateAndSendOtp(email, userId, purpose = 'login') {
        try {
            await database_1.prisma.otpCode.updateMany({
                where: {
                    email,
                    purpose,
                    verified: false,
                },
                data: {
                    verified: true,
                },
            });
            const code = this.generateOtpCode();
            const expiresAt = new Date();
            expiresAt.setMinutes(expiresAt.getMinutes() + this.OTP_EXPIRY_MINUTES);
            const otpRecord = await database_1.prisma.otpCode.create({
                data: {
                    userId,
                    email,
                    code,
                    purpose,
                    expiresAt,
                },
            });
            const emailSent = await email_service_1.emailService.sendOtpEmail(email, code, this.OTP_EXPIRY_MINUTES);
            if (!emailSent) {
                logger_1.logger.error('Failed to send OTP email', { email, otpId: otpRecord.id });
                return {
                    success: false,
                    message: 'Failed to send OTP email. Please try again.',
                };
            }
            logger_1.logger.info('OTP generated and sent', {
                email,
                otpId: otpRecord.id,
                expiresAt
            });
            return {
                success: true,
                message: `OTP sent to ${this.maskEmail(email)}. Valid for ${this.OTP_EXPIRY_MINUTES} minutes.`,
                otpId: otpRecord.id,
            };
        }
        catch (error) {
            logger_1.logger.error('Error generating and sending OTP', { error, email });
            return {
                success: false,
                message: 'Failed to generate OTP. Please try again.',
            };
        }
    }
    async verifyOtp(email, code, purpose = 'login') {
        try {
            const otpRecord = await database_1.prisma.otpCode.findFirst({
                where: {
                    email,
                    purpose,
                    verified: false,
                },
                orderBy: {
                    createdAt: 'desc',
                },
            });
            if (!otpRecord) {
                logger_1.logger.warn('OTP verification failed: No OTP found', { email });
                return {
                    valid: false,
                    message: 'Invalid or expired OTP. Please request a new one.',
                };
            }
            if (new Date() > otpRecord.expiresAt) {
                logger_1.logger.warn('OTP verification failed: Expired', {
                    email,
                    otpId: otpRecord.id
                });
                await database_1.prisma.otpCode.update({
                    where: { id: otpRecord.id },
                    data: { verified: true },
                });
                return {
                    valid: false,
                    message: 'OTP has expired. Please request a new one.',
                };
            }
            if (otpRecord.code !== code) {
                logger_1.logger.warn('OTP verification failed: Invalid code', {
                    email,
                    otpId: otpRecord.id
                });
                return {
                    valid: false,
                    message: 'Invalid OTP code. Please try again.',
                };
            }
            await database_1.prisma.otpCode.update({
                where: { id: otpRecord.id },
                data: { verified: true },
            });
            logger_1.logger.info('OTP verified successfully', {
                email,
                otpId: otpRecord.id,
                userId: otpRecord.userId
            });
            return {
                valid: true,
                message: 'OTP verified successfully',
                userId: otpRecord.userId || undefined,
            };
        }
        catch (error) {
            logger_1.logger.error('Error verifying OTP', { error, email });
            return {
                valid: false,
                message: 'Failed to verify OTP. Please try again.',
            };
        }
    }
    async cleanupExpiredOtps() {
        try {
            const result = await database_1.prisma.otpCode.deleteMany({
                where: {
                    OR: [
                        { expiresAt: { lt: new Date() } },
                        {
                            createdAt: {
                                lt: new Date(Date.now() - 24 * 60 * 60 * 1000)
                            }
                        },
                    ],
                },
            });
            logger_1.logger.info('Cleaned up expired OTP codes', {
                deletedCount: result.count
            });
            return result.count;
        }
        catch (error) {
            logger_1.logger.error('Error cleaning up expired OTPs', { error });
            return 0;
        }
    }
    maskEmail(email) {
        const [local, domain] = email.split('@');
        if (!domain || !local)
            return email;
        const maskedLocal = local.length > 2
            ? `${local[0]}${'*'.repeat(local.length - 2)}${local[local.length - 1]}`
            : local;
        return `${maskedLocal}@${domain}`;
    }
}
exports.OtpService = OtpService;
exports.otpService = new OtpService();
//# sourceMappingURL=otp.service.js.map