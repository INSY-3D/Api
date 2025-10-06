import { prisma } from '@/config/database';
import { logger, logSecurityEvent } from '@/config/logger';
import { 
  Payment, 
  User, 
  UserSession 
} from '@prisma/client';
import { encryptionService } from './encryption.service';
import { 
  CreatePaymentDto, 
  UpdateBeneficiaryDto, 
  SubmitPaymentDto,
  PaymentDto,
  PaymentListResponse,
  PaginationDto
} from '@/types';
import { 
  PaymentStatus, 
  EventType, 
  SecurityRiskLevel 
} from '@/types/enums';
import { 
  isValidAmount, 
  isValidCurrency, 
  isValidSwiftBic, 
  isValidIban,
  sanitizeString,
  maskAccountNumber 
} from '@/types/validation';

// Task 2 Compliant: Payment service with multi-step workflow
export class PaymentService {
  /**
   * Create a new DRAFT payment (Task 2 Compliant: Step 1)
   */
  async createPayment(
    user: User, 
    paymentData: CreatePaymentDto, 
    ipAddress: string, 
    userAgent: string
  ): Promise<PaymentDto> {
    try {
      // Validate input data
      const validationErrors = this.validatePaymentData(paymentData);
      if (validationErrors.length > 0) {
        throw new Error(`Validation failed: ${validationErrors.join(', ')}`);
      }

      // Sanitize inputs
      const sanitizedData = {
        amount: sanitizeString(paymentData.amount, 20),
        currency: sanitizeString(paymentData.currency, 3).toUpperCase(),
        provider: sanitizeString(paymentData.provider, 20),
        idempotencyKey: sanitizeString(paymentData.idempotencyKey, 50),
        reference: paymentData.reference ? sanitizeString(paymentData.reference, 35) : null,
        purpose: paymentData.purpose ? sanitizeString(paymentData.purpose, 140) : null,
      };

      // Check for duplicate idempotency key
      const existingPayment = await prisma.payment.findUnique({
        where: { idempotencyKey: sanitizedData.idempotencyKey },
      });

      if (existingPayment) {
        // Return existing payment (idempotent behavior)
        return await this.mapPaymentToDto(existingPayment);
      }

      // Validate amount
      const amountValue = parseFloat(sanitizedData.amount);
      if (isNaN(amountValue) || amountValue <= 0) {
        throw new Error('Invalid amount format');
      }

      // Log high amounts for monitoring
      if (amountValue > 50000) {
        await this.logSecurityEvent(EventType.SUSPICIOUS_ACTIVITY, 
          `High amount payment created: ${amountValue} ${sanitizedData.currency}`, {
          userId: user.id,
          amount: amountValue,
          currency: sanitizedData.currency,
          ipAddress,
          userAgent,
          riskLevel: SecurityRiskLevel.HIGH,
        });
      }

      // Create DRAFT payment
      const payment = await prisma.payment.create({
        data: {
          userId: user.id,
          amount: amountValue,
          currency: sanitizedData.currency,
          provider: sanitizedData.provider,
          idempotencyKey: sanitizedData.idempotencyKey,
          reference: sanitizedData.reference,
          purpose: sanitizedData.purpose,
          status: PaymentStatus.DRAFT,
        },
      });

      // Log payment creation
      await this.logSecurityEvent(EventType.PAYMENT_CREATED, 
        `Draft payment created: ${payment.id}, ${amountValue} ${sanitizedData.currency}`, {
        userId: user.id,
        paymentId: payment.id,
        amount: amountValue,
        currency: sanitizedData.currency,
        ipAddress,
        userAgent,
        riskLevel: SecurityRiskLevel.LOW,
      });

      return await this.mapPaymentToDto(payment);
    } catch (error) {
      logger.error('Payment creation failed', { error, userId: user.id });
      throw error;
    }
  }

  /**
   * Update payment beneficiary details (Task 2 Compliant: Step 2)
   */
  async updateBeneficiary(
    user: User, 
    paymentId: string, 
    beneficiaryData: UpdateBeneficiaryDto, 
    ipAddress: string, 
    userAgent: string
  ): Promise<PaymentDto> {
    try {
      // Validate input data
      const validationErrors = this.validateBeneficiaryData(beneficiaryData);
      if (validationErrors.length > 0) {
        throw new Error(`Validation failed: ${validationErrors.join(', ')}`);
      }

      // Find payment
      const payment = await prisma.payment.findFirst({
        where: { 
          id: paymentId, 
          userId: user.id 
        },
      });

      if (!payment) {
        throw new Error('Payment not found');
      }

      if (payment.status !== PaymentStatus.DRAFT) {
        throw new Error('Can only update beneficiary for DRAFT payments');
      }

      // Sanitize and validate beneficiary data
      const sanitizedData = {
        beneficiaryName: sanitizeString(beneficiaryData.beneficiaryName, 100),
        beneficiaryAccountNumber: sanitizeString(beneficiaryData.beneficiaryAccountNumber, 18),
        swiftBic: sanitizeString(beneficiaryData.swiftBic, 11).toUpperCase(),
        beneficiaryIban: beneficiaryData.beneficiaryIban ? 
          sanitizeString(beneficiaryData.beneficiaryIban, 34).toUpperCase() : null,
        beneficiaryAddress: sanitizeString(beneficiaryData.beneficiaryAddress, 70),
        beneficiaryCity: sanitizeString(beneficiaryData.beneficiaryCity, 35),
        beneficiaryPostalCode: sanitizeString(beneficiaryData.beneficiaryPostalCode, 16),
        beneficiaryCountry: sanitizeString(beneficiaryData.beneficiaryCountry, 2).toUpperCase(),
      };

      // Update payment with beneficiary details
      const updatedPayment = await prisma.payment.update({
        where: { id: paymentId },
        data: {
          beneficiaryName: sanitizedData.beneficiaryName,
          beneficiaryAccountNumber: sanitizedData.beneficiaryAccountNumber,
          swiftCode: sanitizedData.swiftBic,
          iban: sanitizedData.beneficiaryIban,
          bankAddress: sanitizedData.beneficiaryAddress,
          bankCity: sanitizedData.beneficiaryCity,
          bankPostalCode: sanitizedData.beneficiaryPostalCode,
          bankCountry: sanitizedData.beneficiaryCountry,
        },
      });

      // Log beneficiary update
      await this.logSecurityEvent(EventType.PAYMENT_UPDATED, 
        `Beneficiary details updated for payment: ${paymentId}`, {
        userId: user.id,
        paymentId,
        ipAddress,
        userAgent,
        riskLevel: SecurityRiskLevel.LOW,
      });

      return await this.mapPaymentToDto(updatedPayment);
    } catch (error) {
      logger.error('Beneficiary update failed', { error, userId: user.id, paymentId });
      throw error;
    }
  }

  /**
   * Submit payment for verification (Task 2 Compliant: Step 3)
   */
  async submitPayment(
    user: User, 
    paymentId: string, 
    submitData: SubmitPaymentDto, 
    ipAddress: string, 
    userAgent: string
  ): Promise<PaymentDto> {
    try {
      // Find payment
      const payment = await prisma.payment.findFirst({
        where: { 
          id: paymentId, 
          userId: user.id 
        },
      });

      if (!payment) {
        throw new Error('Payment not found');
      }

      if (payment.status !== PaymentStatus.DRAFT) {
        throw new Error('Can only submit DRAFT payments');
      }

      // Validate that beneficiary details are complete
      if (!payment.beneficiaryName || 
          !payment.beneficiaryAccountNumber || 
          !payment.swiftCode || 
          !payment.bankAddress || 
          !payment.bankCity || 
          !payment.bankPostalCode || 
          !payment.bankCountry) {
        throw new Error('Beneficiary details are incomplete. Please update beneficiary information first.');
      }

      // Sanitize submission data - use provided values or fall back to stored values
      const sanitizedData = {
        reference: submitData.reference ? sanitizeString(submitData.reference, 35) : payment.reference,
        purpose: submitData.purpose ? sanitizeString(submitData.purpose, 140) : payment.purpose,
      };

      // Ensure we have reference and purpose (either from request or stored)
      if (!sanitizedData.reference || !sanitizedData.purpose) {
        throw new Error('Reference and purpose are required for payment submission');
      }

      // Update payment status to PENDING_VERIFICATION
      const updatedPayment = await prisma.payment.update({
        where: { id: paymentId },
        data: {
          reference: sanitizedData.reference,
          purpose: sanitizedData.purpose,
          status: PaymentStatus.PENDING_VERIFICATION,
        },
      });

      // Log payment submission
      await this.logSecurityEvent(EventType.PAYMENT_SUBMITTED, 
        `Payment submitted for verification: ${paymentId}`, {
        userId: user.id,
        paymentId,
        amount: payment.amount,
        currency: payment.currency,
        ipAddress,
        userAgent,
        riskLevel: SecurityRiskLevel.MEDIUM,
      });

      return await this.mapPaymentToDto(updatedPayment);
    } catch (error) {
      logger.error('Payment submission failed', { error, userId: user.id, paymentId });
      throw error;
    }
  }

  /**
   * Get user's payments with pagination
   */
  async getUserPayments(
    user: User, 
    page: number = 1, 
    limit: number = 10
  ): Promise<PaymentListResponse> {
    try {
      const offset = (page - 1) * limit;
      const maxLimit = Math.min(limit, 50); // Max 50 per page

      const [payments, totalCount] = await Promise.all([
        prisma.payment.findMany({
          where: { userId: user.id },
          orderBy: { createdAt: 'desc' },
          skip: offset,
          take: maxLimit,
        }),
        prisma.payment.count({
          where: { userId: user.id },
        }),
      ]);

      const paymentDtos = await Promise.all(payments.map(payment => this.mapPaymentToDto(payment, true)));

      const pagination: PaginationDto = {
        page,
        limit: maxLimit,
        total: totalCount,
        totalPages: Math.ceil(totalCount / maxLimit),
      };

      return {
        payments: paymentDtos,
        pagination,
      };
    } catch (error) {
      logger.error('Get user payments failed', { error, userId: user.id });
      throw error;
    }
  }

  /**
   * Get specific payment by ID
   */
  async getPaymentById(user: User, paymentId: string): Promise<PaymentDto | null> {
    try {
      const payment = await prisma.payment.findFirst({
        where: { 
          id: paymentId, 
          userId: user.id 
        },
      });

      if (!payment) {
        return null;
      }

      return await this.mapPaymentToDto(payment);
    } catch (error) {
      logger.error('Get payment by ID failed', { error, userId: user.id, paymentId });
      throw error;
    }
  }

  /**
   * Delete a DRAFT payment
   */
  async deleteDraftPayment(user: User, paymentId: string): Promise<void> {
    try {
      const payment = await prisma.payment.findFirst({
        where: { 
          id: paymentId, 
          userId: user.id 
        },
      });

      if (!payment) {
        throw new Error('Payment not found');
      }

      if (payment.status !== PaymentStatus.DRAFT) {
        throw new Error('Only DRAFT payments can be deleted');
      }

      await prisma.payment.delete({
        where: { id: paymentId },
      });

      // Log payment deletion
      await this.logSecurityEvent(EventType.PAYMENT_UPDATED, 
        `Draft payment deleted: ${paymentId}`, {
        userId: user.id,
        paymentId,
        riskLevel: SecurityRiskLevel.LOW,
      });
    } catch (error) {
      logger.error('Delete draft payment failed', { error, userId: user.id, paymentId });
      throw error;
    }
  }

  // Private helper methods

  private validatePaymentData(paymentData: CreatePaymentDto): string[] {
    const errors: string[] = [];

    if (!isValidAmount(paymentData.amount)) {
      errors.push('Invalid amount format');
    }

    if (!isValidCurrency(paymentData.currency)) {
      errors.push('Invalid currency format');
    }

    if (!paymentData.provider) {
      errors.push('Provider is required');
    }

    if (!paymentData.idempotencyKey) {
      errors.push('Idempotency key is required');
    }

    return errors;
  }

  private validateBeneficiaryData(beneficiaryData: UpdateBeneficiaryDto): string[] {
    const errors: string[] = [];

    if (!beneficiaryData.beneficiaryName) {
      errors.push('Beneficiary name is required');
    }

    if (!beneficiaryData.beneficiaryAccountNumber) {
      errors.push('Beneficiary account number is required');
    }

    if (!isValidSwiftBic(beneficiaryData.swiftBic)) {
      errors.push('Invalid SWIFT/BIC code format');
    }

    if (beneficiaryData.beneficiaryIban && !isValidIban(beneficiaryData.beneficiaryIban)) {
      errors.push('Invalid IBAN format');
    }

    if (!beneficiaryData.beneficiaryAddress) {
      errors.push('Beneficiary address is required');
    }

    if (!beneficiaryData.beneficiaryCity) {
      errors.push('Beneficiary city is required');
    }

    if (!beneficiaryData.beneficiaryPostalCode) {
      errors.push('Beneficiary postal code is required');
    }

    if (!beneficiaryData.beneficiaryCountry) {
      errors.push('Beneficiary country is required');
    }

    return errors;
  }

  private async mapPaymentToDto(
    payment: Payment & { user?: { fullNameEncrypted?: string; emailEncrypted?: string | null } },
    showSensitive: boolean = false
  ): Promise<PaymentDto> {
    // Decrypt customer information if available
    let customerName: string | undefined;
    let customerEmail: string | undefined;

    if (payment.user?.fullNameEncrypted) {
      try {
        try {
          customerName = await encryptionService.decrypt(JSON.parse(payment.user.fullNameEncrypted));
        } catch {
          customerName = payment.user.fullNameEncrypted as any;
        }
      } catch (error) {
        logger.warn('Failed to decrypt customer name', { paymentId: payment.id, error });
      }
    }

    if (payment.user?.emailEncrypted) {
      try {
        try {
          customerEmail = await encryptionService.decrypt(JSON.parse(payment.user.emailEncrypted));
        } catch {
          customerEmail = payment.user.emailEncrypted as any;
        }
      } catch (error) {
        logger.warn('Failed to decrypt customer email', { paymentId: payment.id, error });
      }
    }

    return {
      id: payment.id,
      amount: Number(payment.amount),
      currency: payment.currency,
      reference: payment.reference || undefined,
      purpose: payment.purpose || undefined,
      beneficiaryName: payment.beneficiaryName || undefined,
      beneficiaryBank: payment.beneficiaryBank || undefined,
      swiftCode: payment.swiftCode || undefined,
      accountNumber: payment.beneficiaryAccountNumber ? 
        (showSensitive ? payment.beneficiaryAccountNumber : maskAccountNumber(payment.beneficiaryAccountNumber)) : undefined,
      iban: payment.iban || undefined,
      status: payment.status,
      createdAt: payment.createdAt,
      updatedAt: payment.updatedAt,
      staffVerifiedAt: payment.staffVerifiedAt || undefined,
      submittedToSwiftAt: payment.submittedToSwiftAt || undefined,
      completedAt: payment.completedAt || undefined,
      customerName,
      customerEmail,
    };
  }

  private async logSecurityEvent(
    eventType: EventType,
    description: string,
    metadata?: any
  ): Promise<void> {
    try {
      await prisma.securityEvent.create({
        data: {
          eventType,
          description,
          metadata: metadata ? JSON.stringify(metadata) : null,
        },
      });

      // Also log to security logger
      logSecurityEvent(eventType, description, metadata);
    } catch (error) {
      logger.error('Failed to log security event', { error });
    }
  }

  /**
   * Get staff payment queue (pending payments for review)
   */
  async getStaffQueue(
    page: number = 1, 
    limit: number = 20
  ): Promise<PaymentListResponse> {
    try {
      const offset = (page - 1) * limit;
      const maxLimit = Math.min(limit, 50); // Max 50 per page

      const [payments, totalCount] = await Promise.all([
        prisma.payment.findMany({
          where: { 
            status: PaymentStatus.PENDING_VERIFICATION // Only pending payments for staff review
          },
          orderBy: { createdAt: 'desc' },
          skip: offset,
          take: maxLimit,
          include: {
            user: {
              select: {
                id: true,
                fullNameEncrypted: true,
                emailEncrypted: true,
              }
            }
          }
        }),
        prisma.payment.count({
          where: { 
            status: PaymentStatus.PENDING_VERIFICATION
          },
        }),
      ]);

      const paymentDtos = await Promise.all(payments.map(payment => this.mapPaymentToDto(payment, true)));

      const pagination: PaginationDto = {
        page,
        limit: maxLimit,
        total: totalCount,
        totalPages: Math.ceil(totalCount / maxLimit),
      };

      return {
        payments: paymentDtos,
        pagination,
      };
    } catch (error) {
      logger.error('Get staff queue failed', { error });
      throw error;
    }
  }

  /**
   * Get staff verified payments
   */
  async getStaffVerified(
    page: number = 1, 
    limit: number = 20
  ): Promise<PaymentListResponse> {
    try {
      const offset = (page - 1) * limit;
      const maxLimit = Math.min(limit, 50); // Max 50 per page

      const [payments, totalCount] = await Promise.all([
        prisma.payment.findMany({
          where: { 
            status: PaymentStatus.VERIFIED // Only verified payments
          },
          orderBy: { staffVerifiedAt: 'desc' },
          skip: offset,
          take: maxLimit,
          include: {
            user: {
              select: {
                id: true,
                fullNameEncrypted: true,
                emailEncrypted: true,
              }
            }
          }
        }),
        prisma.payment.count({
          where: { 
            status: PaymentStatus.VERIFIED
          },
        }),
      ]);

      const paymentDtos = await Promise.all(payments.map(payment => this.mapPaymentToDto(payment, true)));

      const pagination: PaginationDto = {
        page,
        limit: maxLimit,
        total: totalCount,
        totalPages: Math.ceil(totalCount / maxLimit),
      };

      return {
        payments: paymentDtos,
        pagination,
      };
    } catch (error) {
      logger.error('Get staff verified payments failed', { error });
      throw error;
    }
  }

  /**
   * Get staff SWIFT submitted payments
   */
  async getStaffSwift(
    page: number = 1, 
    limit: number = 20
  ): Promise<PaymentListResponse> {
    try {
      const offset = (page - 1) * limit;
      const maxLimit = Math.min(limit, 50); // Max 50 per page

      const [payments, totalCount] = await Promise.all([
        prisma.payment.findMany({
          where: { 
            status: PaymentStatus.SUBMITTED_TO_SWIFT // Only SWIFT submitted payments
          },
          orderBy: { submittedToSwiftAt: 'desc' },
          skip: offset,
          take: maxLimit,
          include: {
            user: {
              select: {
                id: true,
                fullNameEncrypted: true,
                emailEncrypted: true,
              }
            }
          }
        }),
        prisma.payment.count({
          where: { 
            status: PaymentStatus.SUBMITTED_TO_SWIFT
          },
        }),
      ]);

      const paymentDtos = await Promise.all(payments.map(payment => this.mapPaymentToDto(payment)));

      const pagination: PaginationDto = {
        page,
        limit: maxLimit,
        total: totalCount,
        totalPages: Math.ceil(totalCount / maxLimit),
      };

      return {
        payments: paymentDtos,
        pagination,
      };
    } catch (error) {
      logger.error('Get staff SWIFT payments failed', { error });
      throw error;
    }
  }

  /**
   * Verify payment (approve/reject)
   */
  async verifyPayment(
    paymentId: string, 
    action: 'approve' | 'reject', 
    staffUser: User
  ): Promise<PaymentDto> {
    try {
      // Find the payment
      const payment = await prisma.payment.findUnique({
        where: { id: paymentId },
        include: {
          user: {
            select: {
              id: true,
              fullNameEncrypted: true,
              emailEncrypted: true,
            }
          }
        }
      });

      if (!payment) {
        throw new Error('Payment not found');
      }

      // Check if payment is in pending verification status
      if (payment.status !== PaymentStatus.PENDING_VERIFICATION) {
        throw new Error('Payment is not in pending verification status');
      }

      // Update payment status based on action
      const newStatus = action === 'approve' ? PaymentStatus.VERIFIED : PaymentStatus.REJECTED;
      
      const updatedPayment = await prisma.payment.update({
        where: { id: paymentId },
        data: {
          status: newStatus,
          staffVerifiedAt: new Date(),
          staffVerifiedBy: staffUser.id,
        },
        include: {
          user: {
            select: {
              id: true,
              fullNameEncrypted: true,
              emailEncrypted: true,
            }
          }
        }
      });

      // Log security event
      await this.logSecurityEvent(
        action === 'approve' ? EventType.PAYMENT_VERIFIED : EventType.PAYMENT_REJECTED,
        `Payment ${action}d by staff member`,
        {
          paymentId,
          staffUserId: staffUser.id,
          action,
          previousStatus: payment.status,
          newStatus,
        }
      );

      return await this.mapPaymentToDto(updatedPayment, true);
    } catch (error) {
      logger.error('Payment verification failed', { error });
      throw error;
    }
  }

  /**
   * Submit verified payment to SWIFT
   */
  async submitToSwift(
    paymentId: string, 
    staffUser: User
  ): Promise<PaymentDto> {
    try {
      // Find the payment
      const payment = await prisma.payment.findUnique({
        where: { id: paymentId },
        include: {
          user: {
            select: {
              id: true,
              fullNameEncrypted: true,
              emailEncrypted: true,
            }
          }
        }
      });

      if (!payment) {
        throw new Error('Payment not found');
      }

      // Check if payment is in verified status
      if (payment.status !== PaymentStatus.VERIFIED) {
        throw new Error('Payment must be verified before SWIFT submission');
      }

      // Update payment status to submitted to SWIFT
      const updatedPayment = await prisma.payment.update({
        where: { id: paymentId },
        data: {
          status: PaymentStatus.SUBMITTED_TO_SWIFT,
          submittedToSwiftAt: new Date(),
        },
        include: {
          user: {
            select: {
              id: true,
              fullNameEncrypted: true,
              emailEncrypted: true,
            }
          }
        }
      });

      // Log security event
      await this.logSecurityEvent(
        EventType.PAYMENT_SWIFT_SUBMITTED,
        `Payment submitted to SWIFT by staff member`,
        {
          paymentId,
          staffUserId: staffUser.id,
          previousStatus: payment.status,
          newStatus: PaymentStatus.SUBMITTED_TO_SWIFT,
        }
      );

      return await this.mapPaymentToDto(updatedPayment, true);
    } catch (error) {
      logger.error('SWIFT submission failed', { error });
      throw error;
    }
  }
}

// Export singleton instance
export const paymentService = new PaymentService();
