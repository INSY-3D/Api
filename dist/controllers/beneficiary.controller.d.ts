import { Response } from 'express';
import { AuthenticatedRequest } from '@/types';
export declare class BeneficiaryController {
    getUserBeneficiaries(req: AuthenticatedRequest, res: Response): Promise<void>;
    createBeneficiary(req: AuthenticatedRequest, res: Response): Promise<void>;
    deleteBeneficiary(req: AuthenticatedRequest, res: Response): Promise<void>;
}
export declare const beneficiaryController: BeneficiaryController;
//# sourceMappingURL=beneficiary.controller.d.ts.map