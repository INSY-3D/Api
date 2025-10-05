"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.beneficiaryController = exports.BeneficiaryController = void 0;
const beneficiary_service_1 = require("@/services/beneficiary.service");
const logger_1 = require("@/config/logger");
class BeneficiaryController {
    async getUserBeneficiaries(req, res) {
        try {
            if (!req.user) {
                res.status(401).json({
                    success: false,
                    message: 'Authentication required',
                    code: 'AUTH_REQUIRED',
                });
                return;
            }
            const beneficiaries = await beneficiary_service_1.beneficiaryService.getUserBeneficiaries(req.user.id);
            res.status(200).json({
                success: true,
                data: beneficiaries,
            });
        }
        catch (error) {
            logger_1.logger.error('Get user beneficiaries failed', { error });
            res.status(500).json({
                success: false,
                message: 'Failed to retrieve beneficiaries',
                code: 'INTERNAL_ERROR',
            });
        }
    }
    async createBeneficiary(req, res) {
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
            const beneficiary = await beneficiary_service_1.beneficiaryService.createBeneficiary(req.user.id, { fullName, bankName, accountNumber, swiftCode });
            res.status(201).json({
                success: true,
                message: 'Beneficiary created successfully',
                data: beneficiary,
            });
        }
        catch (error) {
            logger_1.logger.error('Create beneficiary failed', { error });
            res.status(500).json({
                success: false,
                message: 'Failed to create beneficiary',
                code: 'INTERNAL_ERROR',
            });
        }
    }
    async deleteBeneficiary(req, res) {
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
            await beneficiary_service_1.beneficiaryService.deleteBeneficiary(req.user.id, beneficiaryId);
            res.status(200).json({
                success: true,
                message: 'Beneficiary deleted successfully',
            });
        }
        catch (error) {
            logger_1.logger.error('Delete beneficiary failed', { error });
            res.status(500).json({
                success: false,
                message: 'Failed to delete beneficiary',
                code: 'INTERNAL_ERROR',
            });
        }
    }
}
exports.BeneficiaryController = BeneficiaryController;
exports.beneficiaryController = new BeneficiaryController();
//# sourceMappingURL=beneficiary.controller.js.map