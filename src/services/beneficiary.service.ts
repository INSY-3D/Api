import { prisma } from '@/config/database';
import { logger } from '@/config/logger';

export interface CreateBeneficiaryDto {
  fullName: string;
  bankName: string;
  accountNumber: string;
  swiftCode: string;
}

export interface BeneficiaryDto {
  id: string;
  fullName: string;
  bankName: string;
  accountNumberMasked: string;
  swiftCode: string;
  createdAt: string;
}

// Task 2 Compliant: Beneficiary service
export class BeneficiaryService {
  /**
   * Get user's beneficiaries
   */
  async getUserBeneficiaries(userId: string): Promise<BeneficiaryDto[]> {
    try {
      const beneficiaries = await prisma.beneficiary.findMany({
        where: { userId },
        orderBy: { createdAt: 'desc' },
      });

      return beneficiaries.map(beneficiary => this.mapBeneficiaryToDto(beneficiary));
    } catch (error) {
      logger.error('Get user beneficiaries failed', { error, userId });
      throw error;
    }
  }

  /**
   * Create a new beneficiary
   */
  async createBeneficiary(userId: string, data: CreateBeneficiaryDto): Promise<BeneficiaryDto> {
    try {
      const beneficiary = await prisma.beneficiary.create({
        data: {
          userId,
          fullName: data.fullName,
          bankName: data.bankName,
          accountNumber: data.accountNumber,
          swiftCode: data.swiftCode,
        },
      });

      return this.mapBeneficiaryToDto(beneficiary);
    } catch (error) {
      logger.error('Create beneficiary failed', { error, userId });
      throw error;
    }
  }

  /**
   * Delete a beneficiary
   */
  async deleteBeneficiary(userId: string, beneficiaryId: string): Promise<void> {
    try {
      // Verify the beneficiary belongs to the user
      const beneficiary = await prisma.beneficiary.findFirst({
        where: {
          id: beneficiaryId,
          userId,
        },
      });

      if (!beneficiary) {
        throw new Error('Beneficiary not found or access denied');
      }

      await prisma.beneficiary.delete({
        where: { id: beneficiaryId },
      });
    } catch (error) {
      logger.error('Delete beneficiary failed', { error, userId, beneficiaryId });
      throw error;
    }
  }

  /**
   * Map beneficiary to DTO
   */
  private mapBeneficiaryToDto(beneficiary: any): BeneficiaryDto {
    return {
      id: beneficiary.id,
      fullName: beneficiary.fullName,
      bankName: beneficiary.bankName,
      accountNumberMasked: this.maskAccountNumber(beneficiary.accountNumber),
      swiftCode: beneficiary.swiftCode,
      createdAt: beneficiary.createdAt.toISOString(),
    };
  }

  /**
   * Mask account number for display
   */
  private maskAccountNumber(accountNumber: string): string {
    if (accountNumber.length <= 4) {
      return '*'.repeat(accountNumber.length);
    }
    return '*'.repeat(accountNumber.length - 4) + accountNumber.slice(-4);
  }
}

// Export singleton instance
export const beneficiaryService = new BeneficiaryService();

