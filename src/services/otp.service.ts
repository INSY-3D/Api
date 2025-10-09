import { prisma } from '@/config/database';
import { logger } from '@/config/logger';
import { emailService } from './email.service';
import crypto from 'crypto';

// Task 2 Compliant: OTP service for email-based authentication
export class OtpService {
  private readonly OTP_LENGTH = 6;
  private readonly OTP_EXPIRY_MINUTES = 10;
  private readonly MAX_ATTEMPTS = 3;

  /**
   * Generate a random 6-digit OTP code
   */
  private generateOtpCode(): string {
    const code = crypto.randomInt(100000, 999999).toString();
    return code;
  }

  /**
   * Generate and send OTP to email
   */
  async generateAndSendOtp(
    email: string, 
    userId?: string, 
    purpose: string = 'login'
  ): Promise<{ success: boolean; message: string; otpId?: string }> {
    try {
      // Invalidate any existing OTP for this email/purpose
      await prisma.otpCode.updateMany({
        where: {
          email,
          purpose,
          verified: false,
        },
        data: {
          verified: true, // Mark as used/invalid
        },
      });

      // Generate new OTP
      const code = this.generateOtpCode();
      const expiresAt = new Date();
      expiresAt.setMinutes(expiresAt.getMinutes() + this.OTP_EXPIRY_MINUTES);

      // Store OTP in database
      const otpRecord = await prisma.otpCode.create({
        data: {
          userId,
          email,
          code,
          purpose,
          expiresAt,
        },
      });

      // Send OTP via email
      const emailSent = await emailService.sendOtpEmail(
        email, 
        code, 
        this.OTP_EXPIRY_MINUTES
      );

      if (!emailSent) {
        logger.error('Failed to send OTP email', { email, otpId: otpRecord.id });
        return {
          success: false,
          message: 'Failed to send OTP email. Please try again.',
        };
      }

      logger.info('OTP generated and sent', { 
        email, 
        otpId: otpRecord.id,
        expiresAt 
      });

      return {
        success: true,
        message: `OTP sent to ${this.maskEmail(email)}. Valid for ${this.OTP_EXPIRY_MINUTES} minutes.`,
        otpId: otpRecord.id,
      };
    } catch (error) {
      logger.error('Error generating and sending OTP', { error, email });
      return {
        success: false,
        message: 'Failed to generate OTP. Please try again.',
      };
    }
  }

  /**
   * Verify OTP code
   */
  async verifyOtp(
    email: string, 
    code: string, 
    purpose: string = 'login'
  ): Promise<{ valid: boolean; message: string; userId?: string }> {
    try {
      // Find valid OTP
      const otpRecord = await prisma.otpCode.findFirst({
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
        logger.warn('OTP verification failed: No OTP found', { email });
        return {
          valid: false,
          message: 'Invalid or expired OTP. Please request a new one.',
        };
      }

      // Check expiry
      if (new Date() > otpRecord.expiresAt) {
        logger.warn('OTP verification failed: Expired', { 
          email, 
          otpId: otpRecord.id 
        });
        
        // Mark as verified (invalid)
        await prisma.otpCode.update({
          where: { id: otpRecord.id },
          data: { verified: true },
        });

        return {
          valid: false,
          message: 'OTP has expired. Please request a new one.',
        };
      }

      // Verify code
      if (otpRecord.code !== code) {
        logger.warn('OTP verification failed: Invalid code', { 
          email, 
          otpId: otpRecord.id 
        });
        
        return {
          valid: false,
          message: 'Invalid OTP code. Please try again.',
        };
      }

      // Mark as verified
      await prisma.otpCode.update({
        where: { id: otpRecord.id },
        data: { verified: true },
      });

      logger.info('OTP verified successfully', { 
        email, 
        otpId: otpRecord.id,
        userId: otpRecord.userId 
      });

      return {
        valid: true,
        message: 'OTP verified successfully',
        userId: otpRecord.userId || undefined,
      };
    } catch (error) {
      logger.error('Error verifying OTP', { error, email });
      return {
        valid: false,
        message: 'Failed to verify OTP. Please try again.',
      };
    }
  }

  /**
   * Clean up expired OTP codes (can be run via cron)
   */
  async cleanupExpiredOtps(): Promise<number> {
    try {
      const result = await prisma.otpCode.deleteMany({
        where: {
          OR: [
            { expiresAt: { lt: new Date() } },
            { 
              createdAt: { 
                lt: new Date(Date.now() - 24 * 60 * 60 * 1000) // 24 hours old
              } 
            },
          ],
        },
      });

      logger.info('Cleaned up expired OTP codes', { 
        deletedCount: result.count 
      });

      return result.count;
    } catch (error) {
      logger.error('Error cleaning up expired OTPs', { error });
      return 0;
    }
  }

  /**
   * Mask email for display (privacy)
   */
  private maskEmail(email: string): string {
    const [local, domain] = email.split('@');
    if (!domain) return email;
    
    const maskedLocal = local.length > 2 
      ? `${local[0]}${'*'.repeat(local.length - 2)}${local[local.length - 1]}`
      : local;
    
    return `${maskedLocal}@${domain}`;
  }
}

// Export singleton instance
export const otpService = new OtpService();

