import { Request, Response } from 'express';
import { beneficiaryService } from '@/services/beneficiary.service';
import { logger } from '@/config/logger';
import { AuthenticatedRequest } from '@/types';

// Task 2 Compliant: Beneficiary controller
export class BeneficiaryController {
  /**
   * Get user's beneficiaries
   * GET /api/v1/beneficiaries
   */
  async getUserBeneficiaries(req: AuthenticatedRequest, res: Response): Promise<void> {
    try {
      if (!req.user) {
        res.status(401).json({
          success: false,
          message: 'Authentication required',
          code: 'AUTH_REQUIRED',
        });
        return;
      }

      const beneficiaries = await beneficiaryService.getUserBeneficiaries(req.user.id);

      res.status(200).json({
        success: true,
        data: beneficiaries,
      });
    } catch (error) {
      logger.error('Get user beneficiaries failed', { error });
      res.status(500).json({
        success: false,
        message: 'Failed to retrieve beneficiaries',
        code: 'INTERNAL_ERROR',
      });
    }
  }

  /**
   * Create a new beneficiary
   * POST /api/v1/beneficiaries
   */
  async createBeneficiary(req: AuthenticatedRequest, res: Response): Promise<void> {
    try {
      const { fullName, bankName, accountNumber, swiftCode } = req.body;

      if (!req.user) {
        res.status(401).json({
          success: false,
          message: 'Authentication required',
          code: 'AUTH_REQUIRED',
        });
        return;
      }

      const beneficiary = await beneficiaryService.createBeneficiary(
        req.user.id,
        { fullName, bankName, accountNumber, swiftCode }
      );

      res.status(201).json({
        success: true,
        message: 'Beneficiary created successfully',
        data: beneficiary,
      });
    } catch (error) {
      logger.error('Create beneficiary failed', { error });
      res.status(500).json({
        success: false,
        message: 'Failed to create beneficiary',
        code: 'INTERNAL_ERROR',
      });
    }
  }

  /**
   * Delete a beneficiary
   * DELETE /api/v1/beneficiaries/:id
   */
  async deleteBeneficiary(req: AuthenticatedRequest, res: Response): Promise<void> {
    try {
      const beneficiaryId = req.params['id'];

      if (!req.user) {
        res.status(401).json({
          success: false,
          message: 'Authentication required',
          code: 'AUTH_REQUIRED',
        });
        return;
      }

      if (!beneficiaryId) {
        res.status(400).json({
          success: false,
          message: 'Beneficiary ID is required',
          code: 'VALIDATION_FAILED',
        });
        return;
      }

      await beneficiaryService.deleteBeneficiary(req.user.id, beneficiaryId);

      res.status(200).json({
        success: true,
        message: 'Beneficiary deleted successfully',
      });
    } catch (error) {
      logger.error('Delete beneficiary failed', { error });
      res.status(500).json({
        success: false,
        message: 'Failed to delete beneficiary',
        code: 'INTERNAL_ERROR',
      });
    }
  }
}

// Export controller instance
export const beneficiaryController = new BeneficiaryController();

