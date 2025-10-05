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
export declare class BeneficiaryService {
    getUserBeneficiaries(userId: string): Promise<BeneficiaryDto[]>;
    createBeneficiary(userId: string, data: CreateBeneficiaryDto): Promise<BeneficiaryDto>;
    deleteBeneficiary(userId: string, beneficiaryId: string): Promise<void>;
    private mapBeneficiaryToDto;
    private maskAccountNumber;
}
export declare const beneficiaryService: BeneficiaryService;
//# sourceMappingURL=beneficiary.service.d.ts.map