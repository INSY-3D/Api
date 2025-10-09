import { config } from '@/config';
import { logger } from '@/config/logger';
import nodemailer from 'nodemailer';

// Task 2 Compliant: Email service for OTP delivery
export class EmailService {
  private isDevelopment = config.server.isDevelopment;
  private transporter: nodemailer.Transporter | null = null;
  private useRealEmail = process.env.SMTP_ENABLED === 'true';

  constructor() {
    // Initialize transporter if SMTP is enabled
    if (this.useRealEmail) {
      this.initializeTransporter();
    }
  }

  /**
   * Initialize SMTP transporter
   */
  private initializeTransporter(): void {
    try {
      this.transporter = nodemailer.createTransport({
        host: process.env.SMTP_HOST || 'smtp.gmail.com',
        port: parseInt(process.env.SMTP_PORT || '587'),
        secure: process.env.SMTP_SECURE === 'true', // true for 465, false for other ports
        auth: {
          user: process.env.SMTP_USER,
          pass: process.env.SMTP_PASS,
        },
      });

      logger.info('SMTP transporter initialized', {
        host: process.env.SMTP_HOST || 'smtp.gmail.com',
        port: process.env.SMTP_PORT || '587',
      });
    } catch (error) {
      logger.error('Failed to initialize SMTP transporter', { error });
    }
  }

  /**
   * Send OTP code via email
   */
  async sendOtpEmail(email: string, code: string, expiresInMinutes: number = 10): Promise<boolean> {
    try {
      logger.info('Sending OTP email', { 
        email: this.maskEmail(email),
        expiresInMinutes,
        useRealEmail: this.useRealEmail
      });

      // Send real email if SMTP is enabled
      if (this.useRealEmail && this.transporter) {
        const emailSent = await this.sendEmailViaSMTP(email, code, expiresInMinutes);
        
        if (emailSent) {
          logger.info('OTP email sent successfully via SMTP', { 
            email: this.maskEmail(email) 
          });
          return true;
        }
        
        logger.error('Failed to send OTP email via SMTP', { 
          email: this.maskEmail(email) 
        });
        return false;
      }

      // Development/Fallback: Log OTP to console
      console.log('\n' + '='.repeat(60));
      console.log('📧 OTP EMAIL (Development Mode)');
      console.log('='.repeat(60));
      console.log(`To: ${email}`);
      console.log(`OTP Code: ${code}`);
      console.log(`Expires in: ${expiresInMinutes} minutes`);
      console.log('='.repeat(60) + '\n');
      
      return true;
    } catch (error) {
      logger.error('Error sending OTP email', { 
        error,
        email: this.maskEmail(email) 
      });
      return false;
    }
  }

  /**
   * Send email via SMTP
   */
  private async sendEmailViaSMTP(
    email: string, 
    code: string, 
    expiresInMinutes: number
  ): Promise<boolean> {
    try {
      if (!this.transporter) {
        logger.error('SMTP transporter not initialized');
        return false;
      }

      const mailOptions = {
        from: process.env.SMTP_FROM || '"NexusPay Security" <noreply@nexuspay.bank>',
        to: email,
        subject: 'NexusPay - Your Login Verification Code',
        html: this.getOtpEmailTemplate(code, expiresInMinutes),
      };

      const info = await this.transporter.sendMail(mailOptions);
      
      logger.info('Email sent successfully', {
        messageId: info.messageId,
        to: this.maskEmail(email),
      });
      
      return true;
    } catch (error) {
      logger.error('SMTP send failed', { error, email: this.maskEmail(email) });
      return false;
    }
  }

  /**
   * Get HTML email template for OTP
   */
  private getOtpEmailTemplate(code: string, expiresInMinutes: number): string {
    return `
      <!DOCTYPE html>
      <html>
      <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <style>
          body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
          .container { max-width: 600px; margin: 0 auto; padding: 20px; }
          .header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 30px; text-align: center; border-radius: 8px 8px 0 0; }
          .content { background: #f9f9f9; padding: 30px; border-radius: 0 0 8px 8px; }
          .otp-code { font-size: 32px; font-weight: bold; letter-spacing: 8px; text-align: center; background: white; padding: 20px; border-radius: 8px; margin: 20px 0; color: #667eea; }
          .warning { background: #fff3cd; border-left: 4px solid #ffc107; padding: 15px; margin: 20px 0; }
          .footer { text-align: center; margin-top: 20px; font-size: 12px; color: #666; }
        </style>
      </head>
      <body>
        <div class="container">
          <div class="header">
            <h1>NexusPay Security</h1>
          </div>
          <div class="content">
            <h2>Your Verification Code</h2>
            <p>You requested a one-time password to access your NexusPay account.</p>
            
            <div class="otp-code">${code}</div>
            
            <div class="warning">
              <strong>⚠️ Security Notice:</strong>
              <ul style="margin: 10px 0 0 0; padding-left: 20px;">
                <li>This code expires in <strong>${expiresInMinutes} minutes</strong></li>
                <li>Never share this code with anyone</li>
                <li>NexusPay will never ask for your code via phone or email</li>
              </ul>
            </div>
            
            <p>If you didn't request this code, please ignore this email and contact our support team immediately.</p>
          </div>
          <div class="footer">
            <p>&copy; ${new Date().getFullYear()} NexusPay International Payments. All rights reserved.</p>
            <p>This is an automated message. Please do not reply to this email.</p>
          </div>
        </div>
      </body>
      </html>
    `;
  }

  /**
   * Mask email for logging (privacy)
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
export const emailService = new EmailService();

