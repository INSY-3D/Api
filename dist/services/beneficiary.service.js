"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.beneficiaryService = exports.BeneficiaryService = void 0;
const database_1 = require("@/config/database");
const logger_1 = require("@/config/logger");
class BeneficiaryService {
    async getUserBeneficiaries(userId) {
        try {
            const beneficiaries = await database_1.prisma.beneficiary.findMany({
                where: { userId },
                orderBy: { createdAt: 'desc' },
            });
            return beneficiaries.map(beneficiary => this.mapBeneficiaryToDto(beneficiary));
        }
        catch (error) {
            logger_1.logger.error('Get user beneficiaries failed', { error, userId });
            throw error;
        }
    }
    async createBeneficiary(userId, data) {
        try {
            const beneficiary = await database_1.prisma.beneficiary.create({
                data: {
                    userId,
                    fullName: data.fullName,
                    bankName: data.bankName,
                    accountNumber: data.accountNumber,
                    swiftCode: data.swiftCode,
                },
            });
            return this.mapBeneficiaryToDto(beneficiary);
        }
        catch (error) {
            logger_1.logger.error('Create beneficiary failed', { error, userId });
            throw error;
        }
    }
    async deleteBeneficiary(userId, beneficiaryId) {
        try {
            const beneficiary = await database_1.prisma.beneficiary.findFirst({
                where: {
                    id: beneficiaryId,
                    userId,
                },
            });
            if (!beneficiary) {
                throw new Error('Beneficiary not found or access denied');
            }
            await database_1.prisma.beneficiary.delete({
                where: { id: beneficiaryId },
            });
        }
        catch (error) {
            logger_1.logger.error('Delete beneficiary failed', { error, userId, beneficiaryId });
            throw error;
        }
    }
    mapBeneficiaryToDto(beneficiary) {
        return {
            id: beneficiary.id,
            fullName: beneficiary.fullName,
            bankName: beneficiary.bankName,
            accountNumberMasked: this.maskAccountNumber(beneficiary.accountNumber),
            swiftCode: beneficiary.swiftCode,
            createdAt: beneficiary.createdAt.toISOString(),
        };
    }
    maskAccountNumber(accountNumber) {
        if (accountNumber.length <= 4) {
            return '*'.repeat(accountNumber.length);
        }
        return '*'.repeat(accountNumber.length - 4) + accountNumber.slice(-4);
    }
}
exports.BeneficiaryService = BeneficiaryService;
exports.beneficiaryService = new BeneficiaryService();
//# sourceMappingURL=beneficiary.service.js.map