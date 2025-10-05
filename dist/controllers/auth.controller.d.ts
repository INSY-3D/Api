import { Request, Response } from 'express';
import { AuthenticatedRequest } from '@/types';
export declare class AuthController {
    register(req: Request, res: Response): Promise<void>;
    login(req: Request, res: Response): Promise<void>;
    logout(req: AuthenticatedRequest, res: Response): Promise<void>;
    getMe(req: AuthenticatedRequest, res: Response): Promise<void>;
    refreshToken(req: Request, res: Response): Promise<void>;
    getCsrfToken(req: Request, res: Response): Promise<void>;
    staffLogin(req: Request, res: Response): Promise<void>;
    private getClientIpAddress;
    private generateCsrfToken;
}
export declare const authController: AuthController;
//# sourceMappingURL=auth.controller.d.ts.map