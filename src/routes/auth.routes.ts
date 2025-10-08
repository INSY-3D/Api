import { Router } from 'express';
import { authController } from '@/controllers/auth.controller';
import { authenticateToken, authRateLimit } from '@/middleware/auth.middleware';
import { validateRequest } from '@/middleware/validation.middleware';
import { 
  registerSchema, 
  loginSchema, 
  refreshTokenSchema 
} from '@/validators/auth.validators';

// Task 2 Compliant: Authentication routes
const router = Router();

/**
 * @swagger
 * /api/v1/register:
 *   post:
 *     summary: Register a new user
 *     tags: [Authentication]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - fullName
 *               - saId
 *               - accountNumber
 *               - password
 *             properties:
 *               fullName:
 *                 type: string
 *                 minLength: 2
 *                 maxLength: 100
 *               saId:
 *                 type: string
 *                 pattern: '^[0-9]{13}$'
 *               accountNumber:
 *                 type: string
 *                 pattern: '^[0-9]{8,12}$'
 *               email:
 *                 type: string
 *                 format: email
 *               password:
 *                 type: string
 *                 minLength: 8
 *     responses:
 *       201:
 *         description: User registered successfully
 *       400:
 *         description: Validation failed or user already exists
 */
router.post('/register', 
  authRateLimit,
  validateRequest(registerSchema),
  authController.register.bind(authController)
);

/**
 * @swagger
 * /api/v1/login:
 *   post:
 *     summary: User login
 *     tags: [Authentication]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - usernameOrEmail
 *               - accountNumber
 *               - password
 *             properties:
 *               usernameOrEmail:
 *                 type: string
 *               accountNumber:
 *                 type: string
 *               password:
 *                 type: string
 *               otp:
 *                 type: string
 *     responses:
 *       200:
 *         description: Login successful
 *       401:
 *         description: Invalid credentials
 */
router.post('/login', 
  authRateLimit,
  validateRequest(loginSchema),
  authController.login.bind(authController)
);

/**
 * @swagger
 * /api/v1/staff-login:
 *   post:
 *     summary: Staff login
 *     tags: [Authentication]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - usernameOrEmail
 *               - accountNumber
 *               - password
 *             properties:
 *               usernameOrEmail:
 *                 type: string
 *               accountNumber:
 *                 type: string
 *               password:
 *                 type: string
 *               otp:
 *                 type: string
 *     responses:
 *       200:
 *         description: Staff login successful
 *       401:
 *         description: Invalid credentials
 *       403:
 *         description: Staff access required
 */
router.post('/staff-login', 
  authRateLimit,
  validateRequest(loginSchema),
  authController.staffLogin.bind(authController)
);

/**
 * @swagger
 * /api/v1/logout:
 *   post:
 *     summary: User logout
 *     tags: [Authentication]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: Logout successful
 *       401:
 *         description: Authentication required
 */
router.post('/logout', 
  authenticateToken,
  authController.logout.bind(authController)
);

/**
 * @swagger
 * /api/v1/me:
 *   get:
 *     summary: Get current user information
 *     tags: [Authentication]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: User information retrieved successfully
 *       401:
 *         description: Authentication required
 */
router.get('/me', 
  authenticateToken,
  authController.getMe.bind(authController)
);

/**
 * @swagger
 * /api/v1/refresh:
 *   post:
 *     summary: Refresh access token
 *     tags: [Authentication]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - refreshToken
 *             properties:
 *               refreshToken:
 *                 type: string
 *     responses:
 *       200:
 *         description: Token refreshed successfully
 *       401:
 *         description: Invalid refresh token
 */
router.post('/refresh', 
  validateRequest(refreshTokenSchema),
  authController.refreshToken.bind(authController)
);

/**
 * @swagger
 * /api/v1/csrf:
 *   get:
 *     summary: Get CSRF token
 *     tags: [Authentication]
 *     responses:
 *       200:
 *         description: CSRF token generated successfully
 */
router.get('/csrf', 
  authController.getCsrfToken.bind(authController)
);

/**
 * @swagger
 * /api/v1/send-otp:
 *   post:
 *     summary: Send OTP to email (for users without registered email)
 *     tags: [Authentication]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - email
 *             properties:
 *               email:
 *                 type: string
 *                 format: email
 *               userId:
 *                 type: string
 *     responses:
 *       200:
 *         description: OTP sent successfully
 *       400:
 *         description: Email is required
 */
router.post('/send-otp',
  authRateLimit,
  authController.sendOtp.bind(authController)
);

export default router;
