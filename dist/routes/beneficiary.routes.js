"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const express_1 = require("express");
const beneficiary_controller_1 = require("@/controllers/beneficiary.controller");
const auth_middleware_1 = require("@/middleware/auth.middleware");
const validation_middleware_1 = require("@/middleware/validation.middleware");
const beneficiary_validators_1 = require("@/validators/beneficiary.validators");
const router = (0, express_1.Router)();
router.get('/', auth_middleware_1.authenticateToken, beneficiary_controller_1.beneficiaryController.getUserBeneficiaries.bind(beneficiary_controller_1.beneficiaryController));
router.post('/', auth_middleware_1.authenticateToken, (0, validation_middleware_1.validateRequest)(beneficiary_validators_1.createBeneficiarySchema), beneficiary_controller_1.beneficiaryController.createBeneficiary.bind(beneficiary_controller_1.beneficiaryController));
router.delete('/:id', auth_middleware_1.authenticateToken, beneficiary_controller_1.beneficiaryController.deleteBeneficiary.bind(beneficiary_controller_1.beneficiaryController));
exports.default = router;
//# sourceMappingURL=beneficiary.routes.js.map