import { User, UserSession } from '@prisma/client';
import { JWTPayload, CreateUserDto, LoginDto, AuthResponse } from '../types';
export declare class AuthService {
    private tryDecrypt;
    hashPassword(password: string): Promise<string>;
    verifyPassword(password: string, hashedPassword: string): Promise<boolean>;
    generateAccessToken(user: User, sessionId: string): string;
    generateRefreshToken(): string;
    verifyAccessToken(token: string): JWTPayload | null;
    verifyRefreshToken(token: string): boolean;
    register(userData: CreateUserDto, ipAddress: string, userAgent: string): Promise<AuthResponse>;
    login(loginData: LoginDto, ipAddress: string, userAgent: string): Promise<AuthResponse>;
    logout(userId: string, sessionId: string): Promise<void>;
    getUserById(userId: string): Promise<User | null>;
    getUserSession(sessionId: string): Promise<UserSession | null>;
    private validateUserData;
    private findUserByCredentials;
    private findUserByLoginCredentials;
    private createUserSession;
    private updateFailedLoginAttempts;
    private logLoginAttempt;
    private logSecurityEvent;
    private mapUserToDto;
    private parseExpiry;
}
export declare const authService: AuthService;
//# sourceMappingURL=auth.service.d.ts.map