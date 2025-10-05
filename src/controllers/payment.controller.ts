import { Request, Response } from 'express';
import { paymentService } from '@/services/payment.service';
import { logger } from '@/config/logger';
import { 
  CreatePaymentDto, 
  UpdateBeneficiaryDto, 
  SubmitPaymentDto 
} from '@/types';
import { AuthenticatedRequest } from '@/types';

// Task 2 Compliant: Payment controller
export class PaymentController {
  /**
   * Create a new DRAFT payment (Task 2 Compliant: Step 1)
   * POST /api/v1/payments
   */
  async createPayment(req: AuthenticatedRequest, res: Response): Promise<void> {
    try {
      const paymentData: CreatePaymentDto = req.body;
      const ipAddress = this.getClientIpAddress(req);
      const userAgent = req.get('User-Agent') || '';

      if (!req.user) {
        res.status(401).json({
          success: false,
          message: 'Authentication required',
          code: 'AUTH_REQUIRED',
        });
        return;
      }

      logger.info('Payment creation attempt', {
        userId: req.user.id,
        userRole: req.user.role,
        amount: paymentData.amount,
        currency: paymentData.currency,
        ipAddress,
      });

      const result = await paymentService.createPayment(
        req.user, 
        paymentData, 
        ipAddress, 
        userAgent
      );

      res.status(201).json({
        success: true,
        message: 'Draft payment created successfully',
        data: {
          paymentId: result.id,
          status: result.status,
          estimatedProcessingTime: 'Add beneficiary details to proceed',
        },
      });
    } catch (error) {
      logger.error('Payment creation failed', { 
        error: error instanceof Error ? error.message : error,
        stack: error instanceof Error ? error.stack : undefined,
        userId: req.user?.id,
        userRole: req.user?.role,
        paymentData: req.body
      });
      
      res.status(400).json({
        success: false,
        message: error instanceof Error ? error.message : 'Payment creation failed',
        code: 'PAYMENT_CREATION_FAILED',
      });
    }
  }

  /**
   * Update payment beneficiary details (Task 2 Compliant: Step 2)
   * PUT /api/v1/payments/:id/beneficiary
   */
  async updateBeneficiary(req: AuthenticatedRequest, res: Response): Promise<void> {
    try {
      const paymentId = req.params['id'];
      const beneficiaryData: UpdateBeneficiaryDto = req.body;
      const ipAddress = this.getClientIpAddress(req);
      const userAgent = req.get('User-Agent') || '';

      if (!paymentId) {
        res.status(400).json({
          success: false,
          message: 'Payment ID is required',
          code: 'PAYMENT_ID_REQUIRED',
        });
        return;
      }

      if (!req.user) {
        res.status(401).json({
          success: false,
          message: 'Authentication required',
          code: 'AUTH_REQUIRED',
        });
        return;
      }

      logger.info('Beneficiary update attempt', {
        userId: req.user.id,
        paymentId,
        ipAddress,
      });

      const result = await paymentService.updateBeneficiary(
        req.user, 
        paymentId, 
        beneficiaryData, 
        ipAddress, 
        userAgent
      );

      res.status(200).json({
        success: true,
        message: 'Beneficiary details updated successfully',
        data: result,
      });
    } catch (error) {
      logger.error('Beneficiary update failed', { error });
      
      res.status(400).json({
        success: false,
        message: error instanceof Error ? error.message : 'Failed to update beneficiary',
        code: 'UPDATE_BENEFICIARY_FAILED',
      });
    }
  }

  /**
   * Submit payment for verification (Task 2 Compliant: Step 3)
   * POST /api/v1/payments/:id/submit
   */
  async submitPayment(req: AuthenticatedRequest, res: Response): Promise<void> {
    try {
      const paymentId = req.params['id'];
      const submitData: SubmitPaymentDto = req.body;
      const ipAddress = this.getClientIpAddress(req);
      const userAgent = req.get('User-Agent') || '';

      if (!paymentId) {
        res.status(400).json({
          success: false,
          message: 'Payment ID is required',
          code: 'PAYMENT_ID_REQUIRED',
        });
        return;
      }

      if (!req.user) {
        res.status(401).json({
          success: false,
          message: 'Authentication required',
          code: 'AUTH_REQUIRED',
        });
        return;
      }

      logger.info('Payment submission attempt', {
        userId: req.user.id,
        paymentId,
        ipAddress,
      });

      const result = await paymentService.submitPayment(
        req.user, 
        paymentId, 
        submitData, 
        ipAddress, 
        userAgent
      );

      res.status(200).json({
        success: true,
        message: 'Payment submitted for staff verification successfully',
        data: result,
      });
    } catch (error) {
      logger.error('Payment submission failed', { error });
      
      res.status(400).json({
        success: false,
        message: error instanceof Error ? error.message : 'Failed to submit payment',
        code: 'SUBMIT_PAYMENT_FAILED',
      });
    }
  }

  /**
   * Get user's payments with pagination
   * GET /api/v1/payments
   */
  async getUserPayments(req: AuthenticatedRequest, res: Response): Promise<void> {
    try {
      const page = parseInt(req.query['page'] as string) || 1;
      const limit = parseInt(req.query['limit'] as string) || 10;

      if (!req.user) {
        res.status(401).json({
          success: false,
          message: 'Authentication required',
          code: 'AUTH_REQUIRED',
        });
        return;
      }

      const result = await paymentService.getUserPayments(req.user, page, limit);

      res.status(200).json({
        success: true,
        data: result,
      });
    } catch (error) {
      logger.error('Get user payments failed', { error });
      
      res.status(500).json({
        success: false,
        message: 'Failed to retrieve payments',
        code: 'PAYMENTS_RETRIEVAL_FAILED',
      });
    }
  }

  /**
   * Get specific payment by ID
   * GET /api/v1/payments/:id
   */
  async getPaymentById(req: AuthenticatedRequest, res: Response): Promise<void> {
    try {
      const paymentId = req.params['id'];

      if (!paymentId) {
        res.status(400).json({
          success: false,
          message: 'Payment ID is required',
          code: 'PAYMENT_ID_REQUIRED',
        });
        return;
      }

      if (!req.user) {
        res.status(401).json({
          success: false,
          message: 'Authentication required',
          code: 'AUTH_REQUIRED',
        });
        return;
      }

      const result = await paymentService.getPaymentById(req.user, paymentId);

      if (!result) {
        res.status(404).json({
          success: false,
          message: 'Payment not found',
          code: 'PAYMENT_NOT_FOUND',
        });
        return;
      }

      res.status(200).json({
        success: true,
        data: result,
      });
    } catch (error) {
      logger.error('Get payment by ID failed', { error });
      
      res.status(500).json({
        success: false,
        message: 'Failed to retrieve payment',
        code: 'PAYMENT_RETRIEVAL_FAILED',
      });
    }
  }

  /**
   * Delete a DRAFT payment
   * DELETE /api/v1/payments/:id
   */
  async deleteDraftPayment(req: AuthenticatedRequest, res: Response): Promise<void> {
    try {
      const paymentId = req.params['id'];

      if (!paymentId) {
        res.status(400).json({
          success: false,
          message: 'Payment ID is required',
          code: 'PAYMENT_ID_REQUIRED',
        });
        return;
      }

      if (!req.user) {
        res.status(401).json({
          success: false,
          message: 'Authentication required',
          code: 'AUTH_REQUIRED',
        });
        return;
      }

      await paymentService.deleteDraftPayment(req.user, paymentId);

      res.status(204).send();
    } catch (error) {
      logger.error('Delete draft payment failed', { error });
      
      res.status(400).json({
        success: false,
        message: error instanceof Error ? error.message : 'Failed to delete draft payment',
        code: 'DELETE_DRAFT_FAILED',
      });
    }
  }

  // Private helper methods

  private getClientIpAddress(req: Request): string {
    return (
      req.headers['x-forwarded-for'] as string ||
      req.headers['x-real-ip'] as string ||
      req.connection.remoteAddress ||
      req.socket.remoteAddress ||
      'unknown'
    );
  }

  /**
   * Get staff payment queue (pending payments for review)
   * GET /api/v1/payments/staff/queue
   */
  async getStaffQueue(req: AuthenticatedRequest, res: Response): Promise<void> {
    try {
      const page = parseInt(req.query['page'] as string) || 1;
      const limit = parseInt(req.query['limit'] as string) || 20;

      if (!req.user) {
        res.status(401).json({
          success: false,
          message: 'Authentication required',
          code: 'AUTH_REQUIRED',
        });
        return;
      }

      // Check if user is staff
      if (req.user.role !== 'staff' && req.user.role !== 'admin') {
        res.status(403).json({
          success: false,
          message: 'Staff access required',
          code: 'ACCESS_DENIED',
        });
        return;
      }

      const result = await paymentService.getStaffQueue(page, limit);

      res.status(200).json({
        success: true,
        data: result,
      });
    } catch (error) {
      logger.error('Get staff queue failed', { error });
      res.status(500).json({
        success: false,
        message: 'Failed to retrieve staff queue',
        code: 'INTERNAL_ERROR',
      });
    }
  }

  /**
   * Get staff verified payments
   * GET /api/v1/payments/staff/verified
   */
  async getStaffVerified(req: AuthenticatedRequest, res: Response): Promise<void> {
    try {
      const page = parseInt(req.query['page'] as string) || 1;
      const limit = parseInt(req.query['limit'] as string) || 20;

      if (!req.user) {
        res.status(401).json({
          success: false,
          message: 'Authentication required',
          code: 'AUTH_REQUIRED',
        });
        return;
      }

      // Check if user is staff
      if (req.user.role !== 'staff' && req.user.role !== 'admin') {
        res.status(403).json({
          success: false,
          message: 'Staff access required',
          code: 'ACCESS_DENIED',
        });
        return;
      }

      const result = await paymentService.getStaffVerified(page, limit);

      res.status(200).json({
        success: true,
        data: result,
      });
    } catch (error) {
      logger.error('Get staff verified payments failed', { error });
      res.status(500).json({
        success: false,
        message: 'Failed to retrieve verified payments',
        code: 'INTERNAL_ERROR',
      });
    }
  }

  /**
   * Get staff SWIFT submitted payments
   * GET /api/v1/payments/staff/swift
   */
  async getStaffSwift(req: AuthenticatedRequest, res: Response): Promise<void> {
    try {
      const page = parseInt(req.query['page'] as string) || 1;
      const limit = parseInt(req.query['limit'] as string) || 20;

      if (!req.user) {
        res.status(401).json({
          success: false,
          message: 'Authentication required',
          code: 'AUTH_REQUIRED',
        });
        return;
      }

      // Check if user is staff
      if (req.user.role !== 'staff' && req.user.role !== 'admin') {
        res.status(403).json({
          success: false,
          message: 'Staff access required',
          code: 'ACCESS_DENIED',
        });
        return;
      }

      const result = await paymentService.getStaffSwift(page, limit);

      res.status(200).json({
        success: true,
        data: result,
      });
    } catch (error) {
      logger.error('Get staff SWIFT payments failed', { error });
      res.status(500).json({
        success: false,
        message: 'Failed to retrieve SWIFT payments',
        code: 'INTERNAL_ERROR',
      });
    }
  }

  /**
   * Verify payment (approve/reject)
   * POST /api/v1/payments/:id/verify
   */
  async verifyPayment(req: AuthenticatedRequest, res: Response): Promise<void> {
    try {
      const paymentId = req.params['id'];
      const { action } = req.body;

      if (!paymentId) {
        res.status(400).json({
          success: false,
          message: 'Payment ID is required',
          code: 'PAYMENT_ID_REQUIRED',
        });
        return;
      }

      if (!req.user) {
        res.status(401).json({
          success: false,
          message: 'Authentication required',
          code: 'AUTH_REQUIRED',
        });
        return;
      }

      // Check if user is staff
      if (req.user.role !== 'staff' && req.user.role !== 'admin') {
        res.status(403).json({
          success: false,
          message: 'Staff access required',
          code: 'ACCESS_DENIED',
        });
        return;
      }

      if (!action || !['approve', 'reject'].includes(action)) {
        res.status(400).json({
          success: false,
          message: 'Action must be either "approve" or "reject"',
          code: 'INVALID_ACTION',
        });
        return;
      }

      const result = await paymentService.verifyPayment(paymentId, action, req.user);

      res.status(200).json({
        success: true,
        message: `Payment ${action}d successfully`,
        data: result,
      });
    } catch (error) {
      logger.error('Payment verification failed', { error });
      res.status(500).json({
        success: false,
        message: error instanceof Error ? error.message : 'Payment verification failed',
        code: 'VERIFICATION_FAILED',
      });
    }
  }

  /**
   * Submit verified payment to SWIFT
   * POST /api/v1/payments/:id/submit-swift
   */
  async submitToSwift(req: AuthenticatedRequest, res: Response): Promise<void> {
    try {
      const paymentId = req.params['id'];

      if (!paymentId) {
        res.status(400).json({
          success: false,
          message: 'Payment ID is required',
          code: 'PAYMENT_ID_REQUIRED',
        });
        return;
      }

      if (!req.user) {
        res.status(401).json({
          success: false,
          message: 'Authentication required',
          code: 'AUTH_REQUIRED',
        });
        return;
      }

      // Check if user is staff
      if (req.user.role !== 'staff' && req.user.role !== 'admin') {
        res.status(403).json({
          success: false,
          message: 'Staff access required',
          code: 'ACCESS_DENIED',
        });
        return;
      }

      const result = await paymentService.submitToSwift(paymentId, req.user);

      res.status(200).json({
        success: true,
        message: 'Payment submitted to SWIFT successfully',
        data: result,
      });
    } catch (error) {
      logger.error('SWIFT submission failed', { error });
      res.status(500).json({
        success: false,
        message: error instanceof Error ? error.message : 'SWIFT submission failed',
        code: 'SWIFT_SUBMISSION_FAILED',
      });
    }
  }
}

// Export controller instance
export const paymentController = new PaymentController();
