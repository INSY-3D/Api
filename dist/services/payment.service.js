"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.paymentService = exports.PaymentService = void 0;
const database_1 = require("../config/database");
const logger_1 = require("../config/logger");
const encryption_service_1 = require("./encryption.service");
const enums_1 = require("../types/enums");
const validation_1 = require("../types/validation");
class PaymentService {
    async createPayment(user, paymentData, ipAddress, userAgent) {
        try {
            const validationErrors = this.validatePaymentData(paymentData);
            if (validationErrors.length > 0) {
                throw new Error(`Validation failed: ${validationErrors.join(', ')}`);
            }
            const sanitizedData = {
                amount: (0, validation_1.sanitizeString)(paymentData.amount, 20),
                currency: (0, validation_1.sanitizeString)(paymentData.currency, 3).toUpperCase(),
                provider: (0, validation_1.sanitizeString)(paymentData.provider, 20),
                idempotencyKey: (0, validation_1.sanitizeString)(paymentData.idempotencyKey, 50),
                reference: paymentData.reference ? (0, validation_1.sanitizeString)(paymentData.reference, 35) : null,
                purpose: paymentData.purpose ? (0, validation_1.sanitizeString)(paymentData.purpose, 140) : null,
            };
            const existingPayment = await database_1.prisma.payment.findUnique({
                where: { idempotencyKey: sanitizedData.idempotencyKey },
            });
            if (existingPayment) {
                return await this.mapPaymentToDto(existingPayment);
            }
            const amountValue = parseFloat(sanitizedData.amount);
            if (isNaN(amountValue) || amountValue <= 0) {
                throw new Error('Invalid amount format');
            }
            if (amountValue > 50000) {
                await this.logSecurityEvent(enums_1.EventType.SUSPICIOUS_ACTIVITY, `High amount payment created: ${amountValue} ${sanitizedData.currency}`, {
                    userId: user.id,
                    amount: amountValue,
                    currency: sanitizedData.currency,
                    ipAddress,
                    userAgent,
                    riskLevel: enums_1.SecurityRiskLevel.HIGH,
                });
            }
            const payment = await database_1.prisma.payment.create({
                data: {
                    userId: user.id,
                    amount: amountValue,
                    currency: sanitizedData.currency,
                    provider: sanitizedData.provider,
                    idempotencyKey: sanitizedData.idempotencyKey,
                    reference: sanitizedData.reference,
                    purpose: sanitizedData.purpose,
                    status: enums_1.PaymentStatus.DRAFT,
                },
            });
            await this.logSecurityEvent(enums_1.EventType.PAYMENT_CREATED, `Draft payment created: ${payment.id}, ${amountValue} ${sanitizedData.currency}`, {
                userId: user.id,
                paymentId: payment.id,
                amount: amountValue,
                currency: sanitizedData.currency,
                ipAddress,
                userAgent,
                riskLevel: enums_1.SecurityRiskLevel.LOW,
            });
            return await this.mapPaymentToDto(payment);
        }
        catch (error) {
            logger_1.logger.error('Payment creation failed', { error, userId: user.id });
            throw error;
        }
    }
    async updateBeneficiary(user, paymentId, beneficiaryData, ipAddress, userAgent) {
        try {
            const validationErrors = this.validateBeneficiaryData(beneficiaryData);
            if (validationErrors.length > 0) {
                throw new Error(`Validation failed: ${validationErrors.join(', ')}`);
            }
            const payment = await database_1.prisma.payment.findFirst({
                where: {
                    id: paymentId,
                    userId: user.id
                },
            });
            if (!payment) {
                throw new Error('Payment not found');
            }
            if (payment.status !== enums_1.PaymentStatus.DRAFT) {
                throw new Error('Can only update beneficiary for DRAFT payments');
            }
            const sanitizedData = {
                beneficiaryName: (0, validation_1.sanitizeString)(beneficiaryData.beneficiaryName, 100),
                beneficiaryAccountNumber: (0, validation_1.sanitizeString)(beneficiaryData.beneficiaryAccountNumber, 18),
                swiftBic: (0, validation_1.sanitizeString)(beneficiaryData.swiftBic, 11).toUpperCase(),
                beneficiaryIban: beneficiaryData.beneficiaryIban ?
                    (0, validation_1.sanitizeString)(beneficiaryData.beneficiaryIban, 34).toUpperCase() : null,
                beneficiaryAddress: (0, validation_1.sanitizeString)(beneficiaryData.beneficiaryAddress, 70),
                beneficiaryCity: (0, validation_1.sanitizeString)(beneficiaryData.beneficiaryCity, 35),
                beneficiaryPostalCode: (0, validation_1.sanitizeString)(beneficiaryData.beneficiaryPostalCode, 16),
                beneficiaryCountry: (0, validation_1.sanitizeString)(beneficiaryData.beneficiaryCountry, 2).toUpperCase(),
            };
            const updatedPayment = await database_1.prisma.payment.update({
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
            await this.logSecurityEvent(enums_1.EventType.PAYMENT_UPDATED, `Beneficiary details updated for payment: ${paymentId}`, {
                userId: user.id,
                paymentId,
                ipAddress,
                userAgent,
                riskLevel: enums_1.SecurityRiskLevel.LOW,
            });
            return await this.mapPaymentToDto(updatedPayment);
        }
        catch (error) {
            logger_1.logger.error('Beneficiary update failed', { error, userId: user.id, paymentId });
            throw error;
        }
    }
    async submitPayment(user, paymentId, submitData, ipAddress, userAgent) {
        try {
            const payment = await database_1.prisma.payment.findFirst({
                where: {
                    id: paymentId,
                    userId: user.id
                },
            });
            if (!payment) {
                throw new Error('Payment not found');
            }
            if (payment.status !== enums_1.PaymentStatus.DRAFT) {
                throw new Error('Can only submit DRAFT payments');
            }
            if (!payment.beneficiaryName ||
                !payment.beneficiaryAccountNumber ||
                !payment.swiftCode ||
                !payment.bankAddress ||
                !payment.bankCity ||
                !payment.bankPostalCode ||
                !payment.bankCountry) {
                throw new Error('Beneficiary details are incomplete. Please update beneficiary information first.');
            }
            const sanitizedData = {
                reference: submitData.reference ? (0, validation_1.sanitizeString)(submitData.reference, 35) : payment.reference,
                purpose: submitData.purpose ? (0, validation_1.sanitizeString)(submitData.purpose, 140) : payment.purpose,
            };
            if (!sanitizedData.reference || !sanitizedData.purpose) {
                throw new Error('Reference and purpose are required for payment submission');
            }
            const updatedPayment = await database_1.prisma.payment.update({
                where: { id: paymentId },
                data: {
                    reference: sanitizedData.reference,
                    purpose: sanitizedData.purpose,
                    status: enums_1.PaymentStatus.PENDING_VERIFICATION,
                },
            });
            await this.logSecurityEvent(enums_1.EventType.PAYMENT_SUBMITTED, `Payment submitted for verification: ${paymentId}`, {
                userId: user.id,
                paymentId,
                amount: payment.amount,
                currency: payment.currency,
                ipAddress,
                userAgent,
                riskLevel: enums_1.SecurityRiskLevel.MEDIUM,
            });
            return await this.mapPaymentToDto(updatedPayment);
        }
        catch (error) {
            logger_1.logger.error('Payment submission failed', { error, userId: user.id, paymentId });
            throw error;
        }
    }
    async getUserPayments(user, page = 1, limit = 10) {
        try {
            const offset = (page - 1) * limit;
            const maxLimit = Math.min(limit, 50);
            const [payments, totalCount] = await Promise.all([
                database_1.prisma.payment.findMany({
                    where: { userId: user.id },
                    orderBy: { createdAt: 'desc' },
                    skip: offset,
                    take: maxLimit,
                }),
                database_1.prisma.payment.count({
                    where: { userId: user.id },
                }),
            ]);
            const paymentDtos = await Promise.all(payments.map(payment => this.mapPaymentToDto(payment, true)));
            const pagination = {
                page,
                limit: maxLimit,
                total: totalCount,
                totalPages: Math.ceil(totalCount / maxLimit),
            };
            return {
                payments: paymentDtos,
                pagination,
            };
        }
        catch (error) {
            logger_1.logger.error('Get user payments failed', { error, userId: user.id });
            throw error;
        }
    }
    async getPaymentById(user, paymentId) {
        try {
            const payment = await database_1.prisma.payment.findFirst({
                where: {
                    id: paymentId,
                    userId: user.id
                },
            });
            if (!payment) {
                return null;
            }
            return await this.mapPaymentToDto(payment);
        }
        catch (error) {
            logger_1.logger.error('Get payment by ID failed', { error, userId: user.id, paymentId });
            throw error;
        }
    }
    async deleteDraftPayment(user, paymentId) {
        try {
            const payment = await database_1.prisma.payment.findFirst({
                where: {
                    id: paymentId,
                    userId: user.id
                },
            });
            if (!payment) {
                throw new Error('Payment not found');
            }
            if (payment.status !== enums_1.PaymentStatus.DRAFT) {
                throw new Error('Only DRAFT payments can be deleted');
            }
            await database_1.prisma.payment.delete({
                where: { id: paymentId },
            });
            await this.logSecurityEvent(enums_1.EventType.PAYMENT_UPDATED, `Draft payment deleted: ${paymentId}`, {
                userId: user.id,
                paymentId,
                riskLevel: enums_1.SecurityRiskLevel.LOW,
            });
        }
        catch (error) {
            logger_1.logger.error('Delete draft payment failed', { error, userId: user.id, paymentId });
            throw error;
        }
    }
    validatePaymentData(paymentData) {
        const errors = [];
        if (!(0, validation_1.isValidAmount)(paymentData.amount)) {
            errors.push('Invalid amount format');
        }
        if (!(0, validation_1.isValidCurrency)(paymentData.currency)) {
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
    validateBeneficiaryData(beneficiaryData) {
        const errors = [];
        if (!beneficiaryData.beneficiaryName) {
            errors.push('Beneficiary name is required');
        }
        if (!beneficiaryData.beneficiaryAccountNumber) {
            errors.push('Beneficiary account number is required');
        }
        if (!(0, validation_1.isValidSwiftBic)(beneficiaryData.swiftBic)) {
            errors.push('Invalid SWIFT/BIC code format');
        }
        if (beneficiaryData.beneficiaryIban && !(0, validation_1.isValidIban)(beneficiaryData.beneficiaryIban)) {
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
    async mapPaymentToDto(payment, showSensitive = false) {
        let customerName;
        let customerEmail;
        if (payment.user?.fullNameEncrypted) {
            try {
                try {
                    customerName = await encryption_service_1.encryptionService.decrypt(JSON.parse(payment.user.fullNameEncrypted));
                }
                catch {
                    customerName = payment.user.fullNameEncrypted;
                }
            }
            catch (error) {
                logger_1.logger.warn('Failed to decrypt customer name', { paymentId: payment.id, error });
            }
        }
        if (payment.user?.emailEncrypted) {
            try {
                try {
                    customerEmail = await encryption_service_1.encryptionService.decrypt(JSON.parse(payment.user.emailEncrypted));
                }
                catch {
                    customerEmail = payment.user.emailEncrypted;
                }
            }
            catch (error) {
                logger_1.logger.warn('Failed to decrypt customer email', { paymentId: payment.id, error });
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
                (showSensitive ? payment.beneficiaryAccountNumber : (0, validation_1.maskAccountNumber)(payment.beneficiaryAccountNumber)) : undefined,
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
    async logSecurityEvent(eventType, description, metadata) {
        try {
            await database_1.prisma.securityEvent.create({
                data: {
                    eventType,
                    description,
                    metadata: metadata ? JSON.stringify(metadata) : null,
                },
            });
            (0, logger_1.logSecurityEvent)(eventType, description, metadata);
        }
        catch (error) {
            logger_1.logger.error('Failed to log security event', { error });
        }
    }
    async getStaffQueue(page = 1, limit = 20) {
        try {
            const offset = (page - 1) * limit;
            const maxLimit = Math.min(limit, 50);
            const [payments, totalCount] = await Promise.all([
                database_1.prisma.payment.findMany({
                    where: {
                        status: enums_1.PaymentStatus.PENDING_VERIFICATION
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
                database_1.prisma.payment.count({
                    where: {
                        status: enums_1.PaymentStatus.PENDING_VERIFICATION
                    },
                }),
            ]);
            const paymentDtos = await Promise.all(payments.map(payment => this.mapPaymentToDto(payment, true)));
            const pagination = {
                page,
                limit: maxLimit,
                total: totalCount,
                totalPages: Math.ceil(totalCount / maxLimit),
            };
            return {
                payments: paymentDtos,
                pagination,
            };
        }
        catch (error) {
            logger_1.logger.error('Get staff queue failed', { error });
            throw error;
        }
    }
    async getStaffVerified(page = 1, limit = 20) {
        try {
            const offset = (page - 1) * limit;
            const maxLimit = Math.min(limit, 50);
            const [payments, totalCount] = await Promise.all([
                database_1.prisma.payment.findMany({
                    where: {
                        status: enums_1.PaymentStatus.VERIFIED
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
                database_1.prisma.payment.count({
                    where: {
                        status: enums_1.PaymentStatus.VERIFIED
                    },
                }),
            ]);
            const paymentDtos = await Promise.all(payments.map(payment => this.mapPaymentToDto(payment, true)));
            const pagination = {
                page,
                limit: maxLimit,
                total: totalCount,
                totalPages: Math.ceil(totalCount / maxLimit),
            };
            return {
                payments: paymentDtos,
                pagination,
            };
        }
        catch (error) {
            logger_1.logger.error('Get staff verified payments failed', { error });
            throw error;
        }
    }
    async getStaffSwift(page = 1, limit = 20) {
        try {
            const offset = (page - 1) * limit;
            const maxLimit = Math.min(limit, 50);
            const [payments, totalCount] = await Promise.all([
                database_1.prisma.payment.findMany({
                    where: {
                        status: enums_1.PaymentStatus.SUBMITTED_TO_SWIFT
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
                database_1.prisma.payment.count({
                    where: {
                        status: enums_1.PaymentStatus.SUBMITTED_TO_SWIFT
                    },
                }),
            ]);
            const paymentDtos = await Promise.all(payments.map(payment => this.mapPaymentToDto(payment)));
            const pagination = {
                page,
                limit: maxLimit,
                total: totalCount,
                totalPages: Math.ceil(totalCount / maxLimit),
            };
            return {
                payments: paymentDtos,
                pagination,
            };
        }
        catch (error) {
            logger_1.logger.error('Get staff SWIFT payments failed', { error });
            throw error;
        }
    }
    async verifyPayment(paymentId, action, staffUser) {
        try {
            const payment = await database_1.prisma.payment.findUnique({
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
            if (payment.status !== enums_1.PaymentStatus.PENDING_VERIFICATION) {
                throw new Error('Payment is not in pending verification status');
            }
            const newStatus = action === 'approve' ? enums_1.PaymentStatus.VERIFIED : enums_1.PaymentStatus.REJECTED;
            const updatedPayment = await database_1.prisma.payment.update({
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
            await this.logSecurityEvent(action === 'approve' ? enums_1.EventType.PAYMENT_VERIFIED : enums_1.EventType.PAYMENT_REJECTED, `Payment ${action}d by staff member`, {
                paymentId,
                staffUserId: staffUser.id,
                action,
                previousStatus: payment.status,
                newStatus,
            });
            return await this.mapPaymentToDto(updatedPayment, true);
        }
        catch (error) {
            logger_1.logger.error('Payment verification failed', { error });
            throw error;
        }
    }
    async submitToSwift(paymentId, staffUser) {
        try {
            const payment = await database_1.prisma.payment.findUnique({
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
            if (payment.status !== enums_1.PaymentStatus.VERIFIED) {
                throw new Error('Payment must be verified before SWIFT submission');
            }
            const updatedPayment = await database_1.prisma.payment.update({
                where: { id: paymentId },
                data: {
                    status: enums_1.PaymentStatus.SUBMITTED_TO_SWIFT,
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
            await this.logSecurityEvent(enums_1.EventType.PAYMENT_SWIFT_SUBMITTED, `Payment submitted to SWIFT by staff member`, {
                paymentId,
                staffUserId: staffUser.id,
                previousStatus: payment.status,
                newStatus: enums_1.PaymentStatus.SUBMITTED_TO_SWIFT,
            });
            return await this.mapPaymentToDto(updatedPayment, true);
        }
        catch (error) {
            logger_1.logger.error('SWIFT submission failed', { error });
            throw error;
        }
    }
}
exports.PaymentService = PaymentService;
exports.paymentService = new PaymentService();
//# sourceMappingURL=payment.service.js.map