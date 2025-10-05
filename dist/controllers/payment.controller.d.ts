import { Response } from 'express';
import { AuthenticatedRequest } from '@/types';
export declare class PaymentController {
    createPayment(req: AuthenticatedRequest, res: Response): Promise<void>;
    updateBeneficiary(req: AuthenticatedRequest, res: Response): Promise<void>;
    submitPayment(req: AuthenticatedRequest, res: Response): Promise<void>;
    getUserPayments(req: AuthenticatedRequest, res: Response): Promise<void>;
    getPaymentById(req: AuthenticatedRequest, res: Response): Promise<void>;
    deleteDraftPayment(req: AuthenticatedRequest, res: Response): Promise<void>;
    private getClientIpAddress;
    getStaffQueue(req: AuthenticatedRequest, res: Response): Promise<void>;
    getStaffVerified(req: AuthenticatedRequest, res: Response): Promise<void>;
    getStaffSwift(req: AuthenticatedRequest, res: Response): Promise<void>;
    verifyPayment(req: AuthenticatedRequest, res: Response): Promise<void>;
    submitToSwift(req: AuthenticatedRequest, res: Response): Promise<void>;
}
export declare const paymentController: PaymentController;
//# sourceMappingURL=payment.controller.d.ts.map