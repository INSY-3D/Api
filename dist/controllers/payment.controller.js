"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.paymentController = exports.PaymentController = void 0;
const payment_service_1 = require("../services/payment.service");
const logger_1 = require("../config/logger");
class PaymentController {
    async createPayment(req, res) {
        try {
            const paymentData = req.body;
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
            logger_1.logger.info('Payment creation attempt', {
                userId: req.user.id,
                userRole: req.user.role,
                amount: paymentData.amount,
                currency: paymentData.currency,
                ipAddress,
            });
            const result = await payment_service_1.paymentService.createPayment(req.user, paymentData, ipAddress, userAgent);
            res.status(201).json({
                success: true,
                message: 'Draft payment created successfully',
                data: {
                    paymentId: result.id,
                    status: result.status,
                    estimatedProcessingTime: 'Add beneficiary details to proceed',
                },
            });
        }
        catch (error) {
            logger_1.logger.error('Payment creation failed', {
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
    async updateBeneficiary(req, res) {
        try {
            const paymentId = req.params['id'];
            const beneficiaryData = req.body;
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
            logger_1.logger.info('Beneficiary update attempt', {
                userId: req.user.id,
                paymentId,
                ipAddress,
            });
            const result = await payment_service_1.paymentService.updateBeneficiary(req.user, paymentId, beneficiaryData, ipAddress, userAgent);
            res.status(200).json({
                success: true,
                message: 'Beneficiary details updated successfully',
                data: result,
            });
        }
        catch (error) {
            logger_1.logger.error('Beneficiary update failed', { error });
            res.status(400).json({
                success: false,
                message: error instanceof Error ? error.message : 'Failed to update beneficiary',
                code: 'UPDATE_BENEFICIARY_FAILED',
            });
        }
    }
    async submitPayment(req, res) {
        try {
            const paymentId = req.params['id'];
            const submitData = req.body;
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
            logger_1.logger.info('Payment submission attempt', {
                userId: req.user.id,
                paymentId,
                ipAddress,
            });
            const result = await payment_service_1.paymentService.submitPayment(req.user, paymentId, submitData, ipAddress, userAgent);
            res.status(200).json({
                success: true,
                message: 'Payment submitted for staff verification successfully',
                data: result,
            });
        }
        catch (error) {
            logger_1.logger.error('Payment submission failed', { error });
            res.status(400).json({
                success: false,
                message: error instanceof Error ? error.message : 'Failed to submit payment',
                code: 'SUBMIT_PAYMENT_FAILED',
            });
        }
    }
    async getUserPayments(req, res) {
        try {
            const page = parseInt(req.query['page']) || 1;
            const limit = parseInt(req.query['limit']) || 10;
            if (!req.user) {
                res.status(401).json({
                    success: false,
                    message: 'Authentication required',
                    code: 'AUTH_REQUIRED',
                });
                return;
            }
            const result = await payment_service_1.paymentService.getUserPayments(req.user, page, limit);
            res.status(200).json({
                success: true,
                data: result,
            });
        }
        catch (error) {
            logger_1.logger.error('Get user payments failed', { error });
            res.status(500).json({
                success: false,
                message: 'Failed to retrieve payments',
                code: 'PAYMENTS_RETRIEVAL_FAILED',
            });
        }
    }
    async getPaymentById(req, res) {
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
            const result = await payment_service_1.paymentService.getPaymentById(req.user, paymentId);
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
        }
        catch (error) {
            logger_1.logger.error('Get payment by ID failed', { error });
            res.status(500).json({
                success: false,
                message: 'Failed to retrieve payment',
                code: 'PAYMENT_RETRIEVAL_FAILED',
            });
        }
    }
    async deleteDraftPayment(req, res) {
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
            await payment_service_1.paymentService.deleteDraftPayment(req.user, paymentId);
            res.status(204).send();
        }
        catch (error) {
            logger_1.logger.error('Delete draft payment failed', { error });
            res.status(400).json({
                success: false,
                message: error instanceof Error ? error.message : 'Failed to delete draft payment',
                code: 'DELETE_DRAFT_FAILED',
            });
        }
    }
    getClientIpAddress(req) {
        return (req.headers['x-forwarded-for'] ||
            req.headers['x-real-ip'] ||
            req.connection.remoteAddress ||
            req.socket.remoteAddress ||
            'unknown');
    }
    async getStaffQueue(req, res) {
        try {
            const page = parseInt(req.query['page']) || 1;
            const limit = parseInt(req.query['limit']) || 20;
            if (!req.user) {
                res.status(401).json({
                    success: false,
                    message: 'Authentication required',
                    code: 'AUTH_REQUIRED',
                });
                return;
            }
            if (req.user.role !== 'staff' && req.user.role !== 'admin') {
                res.status(403).json({
                    success: false,
                    message: 'Staff access required',
                    code: 'ACCESS_DENIED',
                });
                return;
            }
            const result = await payment_service_1.paymentService.getStaffQueue(page, limit);
            res.status(200).json({
                success: true,
                data: result,
            });
        }
        catch (error) {
            logger_1.logger.error('Get staff queue failed', { error });
            res.status(500).json({
                success: false,
                message: 'Failed to retrieve staff queue',
                code: 'INTERNAL_ERROR',
            });
        }
    }
    async getStaffVerified(req, res) {
        try {
            const page = parseInt(req.query['page']) || 1;
            const limit = parseInt(req.query['limit']) || 20;
            if (!req.user) {
                res.status(401).json({
                    success: false,
                    message: 'Authentication required',
                    code: 'AUTH_REQUIRED',
                });
                return;
            }
            if (req.user.role !== 'staff' && req.user.role !== 'admin') {
                res.status(403).json({
                    success: false,
                    message: 'Staff access required',
                    code: 'ACCESS_DENIED',
                });
                return;
            }
            const result = await payment_service_1.paymentService.getStaffVerified(page, limit);
            res.status(200).json({
                success: true,
                data: result,
            });
        }
        catch (error) {
            logger_1.logger.error('Get staff verified payments failed', { error });
            res.status(500).json({
                success: false,
                message: 'Failed to retrieve verified payments',
                code: 'INTERNAL_ERROR',
            });
        }
    }
    async getStaffSwift(req, res) {
        try {
            const page = parseInt(req.query['page']) || 1;
            const limit = parseInt(req.query['limit']) || 20;
            if (!req.user) {
                res.status(401).json({
                    success: false,
                    message: 'Authentication required',
                    code: 'AUTH_REQUIRED',
                });
                return;
            }
            if (req.user.role !== 'staff' && req.user.role !== 'admin') {
                res.status(403).json({
                    success: false,
                    message: 'Staff access required',
                    code: 'ACCESS_DENIED',
                });
                return;
            }
            const result = await payment_service_1.paymentService.getStaffSwift(page, limit);
            res.status(200).json({
                success: true,
                data: result,
            });
        }
        catch (error) {
            logger_1.logger.error('Get staff SWIFT payments failed', { error });
            res.status(500).json({
                success: false,
                message: 'Failed to retrieve SWIFT payments',
                code: 'INTERNAL_ERROR',
            });
        }
    }
    async verifyPayment(req, res) {
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
            const result = await payment_service_1.paymentService.verifyPayment(paymentId, action, req.user);
            res.status(200).json({
                success: true,
                message: `Payment ${action}d successfully`,
                data: result,
            });
        }
        catch (error) {
            logger_1.logger.error('Payment verification failed', { error });
            res.status(500).json({
                success: false,
                message: error instanceof Error ? error.message : 'Payment verification failed',
                code: 'VERIFICATION_FAILED',
            });
        }
    }
    async submitToSwift(req, res) {
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
            if (req.user.role !== 'staff' && req.user.role !== 'admin') {
                res.status(403).json({
                    success: false,
                    message: 'Staff access required',
                    code: 'ACCESS_DENIED',
                });
                return;
            }
            const result = await payment_service_1.paymentService.submitToSwift(paymentId, req.user);
            res.status(200).json({
                success: true,
                message: 'Payment submitted to SWIFT successfully',
                data: result,
            });
        }
        catch (error) {
            logger_1.logger.error('SWIFT submission failed', { error });
            res.status(500).json({
                success: false,
                message: error instanceof Error ? error.message : 'SWIFT submission failed',
                code: 'SWIFT_SUBMISSION_FAILED',
            });
        }
    }
}
exports.PaymentController = PaymentController;
exports.paymentController = new PaymentController();
//# sourceMappingURL=payment.controller.js.map