import { User } from '@prisma/client';
import { CreatePaymentDto, UpdateBeneficiaryDto, SubmitPaymentDto, PaymentDto, PaymentListResponse } from '@/types';
export declare class PaymentService {
    createPayment(user: User, paymentData: CreatePaymentDto, ipAddress: string, userAgent: string): Promise<PaymentDto>;
    updateBeneficiary(user: User, paymentId: string, beneficiaryData: UpdateBeneficiaryDto, ipAddress: string, userAgent: string): Promise<PaymentDto>;
    submitPayment(user: User, paymentId: string, submitData: SubmitPaymentDto, ipAddress: string, userAgent: string): Promise<PaymentDto>;
    getUserPayments(user: User, page?: number, limit?: number): Promise<PaymentListResponse>;
    getPaymentById(user: User, paymentId: string): Promise<PaymentDto | null>;
    deleteDraftPayment(user: User, paymentId: string): Promise<void>;
    private validatePaymentData;
    private validateBeneficiaryData;
    private mapPaymentToDto;
    private logSecurityEvent;
    getStaffQueue(page?: number, limit?: number): Promise<PaymentListResponse>;
    getStaffVerified(page?: number, limit?: number): Promise<PaymentListResponse>;
    getStaffSwift(page?: number, limit?: number): Promise<PaymentListResponse>;
    verifyPayment(paymentId: string, action: 'approve' | 'reject', staffUser: User): Promise<PaymentDto>;
    submitToSwift(paymentId: string, staffUser: User): Promise<PaymentDto>;
}
export declare const paymentService: PaymentService;
//# sourceMappingURL=payment.service.d.ts.map