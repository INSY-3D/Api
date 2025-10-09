"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const express_1 = require("express");
const auth_controller_1 = require("../controllers/auth.controller");
const auth_middleware_1 = require("../middleware/auth.middleware");
const validation_middleware_1 = require("../middleware/validation.middleware");
const auth_validators_1 = require("../validators/auth.validators");
const router = (0, express_1.Router)();
router.post('/register', auth_middleware_1.authRateLimit, (0, validation_middleware_1.validateRequest)(auth_validators_1.registerSchema), auth_controller_1.authController.register.bind(auth_controller_1.authController));
router.post('/login', auth_middleware_1.authRateLimit, (0, validation_middleware_1.validateRequest)(auth_validators_1.loginSchema), auth_controller_1.authController.login.bind(auth_controller_1.authController));
router.post('/staff-login', auth_middleware_1.authRateLimit, (0, validation_middleware_1.validateRequest)(auth_validators_1.loginSchema), auth_controller_1.authController.staffLogin.bind(auth_controller_1.authController));
router.post('/logout', auth_middleware_1.authenticateToken, auth_controller_1.authController.logout.bind(auth_controller_1.authController));
router.get('/me', auth_middleware_1.authenticateToken, auth_controller_1.authController.getMe.bind(auth_controller_1.authController));
router.post('/refresh', (0, validation_middleware_1.validateRequest)(auth_validators_1.refreshTokenSchema), auth_controller_1.authController.refreshToken.bind(auth_controller_1.authController));
router.get('/csrf', auth_controller_1.authController.getCsrfToken.bind(auth_controller_1.authController));
router.post('/send-otp', auth_middleware_1.authRateLimit, auth_controller_1.authController.sendOtp.bind(auth_controller_1.authController));
exports.default = router;
//# sourceMappingURL=auth.routes.js.map