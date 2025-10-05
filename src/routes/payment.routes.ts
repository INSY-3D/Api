import { Router } from 'express';
import { paymentController } from '@/controllers/payment.controller';
import { authenticateToken, requireCustomer } from '@/middleware/auth.middleware';
import { validateRequest } from '@/middleware/validation.middleware';
import { 
  createPaymentSchema, 
  updateBeneficiarySchema, 
  submitPaymentSchema 
} from '@/validators/payment.validators';

// Task 2 Compliant: Payment routes
const router = Router();

/**
 * @swagger
 * /api/v1/payments:
 *   post:
 *     summary: Create a new DRAFT payment
 *     tags: [Payments]
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - amount
 *               - currency
 *               - provider
 *               - idempotencyKey
 *             properties:
 *               amount:
 *                 type: string
 *                 pattern: '^\d{1,12}(\.\d{1,2})?$'
 *               currency:
 *                 type: string
 *                 pattern: '^[A-Z]{3}$'
 *               provider:
 *                 type: string
 *                 default: 'SWIFT'
 *               idempotencyKey:
 *                 type: string
 *                 maxLength: 50
 *     responses:
 *       201:
 *         description: Draft payment created successfully
 *       400:
 *         description: Validation failed
 *       401:
 *         description: Authentication required
 */
router.post('/', 
  authenticateToken,
  requireCustomer,
  validateRequest(createPaymentSchema),
  paymentController.createPayment.bind(paymentController)
);

/**
 * @swagger
 * /api/v1/payments:
 *   get:
 *     summary: Get user's payments with pagination
 *     tags: [Payments]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: query
 *         name: page
 *         schema:
 *           type: integer
 *           minimum: 1
 *           default: 1
 *       - in: query
 *         name: limit
 *         schema:
 *           type: integer
 *           minimum: 1
 *           maximum: 50
 *           default: 10
 *     responses:
 *       200:
 *         description: Payments retrieved successfully
 *       401:
 *         description: Authentication required
 */
router.get('/', 
  authenticateToken,
  requireCustomer,
  paymentController.getUserPayments.bind(paymentController)
);

/**
 * @swagger
 * /api/v1/payments/staff/queue:
 *   get:
 *     summary: Get staff payment queue (pending payments for review)
 *     tags: [Payments]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: query
 *         name: page
 *         schema:
 *           type: integer
 *           minimum: 1
 *           default: 1
 *         description: Page number
 *       - in: query
 *         name: limit
 *         schema:
 *           type: integer
 *           minimum: 1
 *           maximum: 50
 *           default: 20
 *         description: Number of payments per page
 *     responses:
 *       200:
 *         description: Staff queue retrieved successfully
 *       401:
 *         description: Authentication required
 *       403:
 *         description: Staff access required
 */
router.get('/staff/queue',
  authenticateToken,
  paymentController.getStaffQueue.bind(paymentController)
);

/**
 * @swagger
 * /api/v1/payments/staff/verified:
 *   get:
 *     summary: Get staff verified payments
 *     tags: [Payments]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: query
 *         name: page
 *         schema:
 *           type: integer
 *           minimum: 1
 *           default: 1
 *         description: Page number
 *       - in: query
 *         name: limit
 *         schema:
 *           type: integer
 *           minimum: 1
 *           maximum: 50
 *           default: 20
 *         description: Number of payments per page
 *     responses:
 *       200:
 *         description: Verified payments retrieved successfully
 *       401:
 *         description: Authentication required
 *       403:
 *         description: Staff access required
 */
router.get('/staff/verified',
  authenticateToken,
  paymentController.getStaffVerified.bind(paymentController)
);

/**
 * @swagger
 * /api/v1/payments/staff/swift:
 *   get:
 *     summary: Get staff SWIFT submitted payments
 *     tags: [Payments]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: query
 *         name: page
 *         schema:
 *           type: integer
 *           minimum: 1
 *           default: 1
 *         description: Page number
 *       - in: query
 *         name: limit
 *         schema:
 *           type: integer
 *           minimum: 1
 *           maximum: 50
 *           default: 20
 *         description: Number of payments per page
 *     responses:
 *       200:
 *         description: SWIFT submitted payments retrieved successfully
 *       401:
 *         description: Authentication required
 *       403:
 *         description: Staff access required
 */
router.get('/staff/swift',
  authenticateToken,
  paymentController.getStaffSwift.bind(paymentController)
);

/**
 * @swagger
 * /api/v1/payments/{id}:
 *   get:
 *     summary: Get specific payment by ID
 *     tags: [Payments]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: string
 *     responses:
 *       200:
 *         description: Payment retrieved successfully
 *       404:
 *         description: Payment not found
 *       401:
 *         description: Authentication required
 */
router.get('/:id', 
  authenticateToken,
  requireCustomer,
  paymentController.getPaymentById.bind(paymentController)
);

/**
 * @swagger
 * /api/v1/payments/{id}/beneficiary:
 *   put:
 *     summary: Update payment beneficiary details
 *     tags: [Payments]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: string
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - beneficiaryName
 *               - beneficiaryAccountNumber
 *               - swiftBic
 *               - beneficiaryAddress
 *               - beneficiaryCity
 *               - beneficiaryPostalCode
 *               - beneficiaryCountry
 *             properties:
 *               beneficiaryName:
 *                 type: string
 *                 maxLength: 100
 *               beneficiaryAccountNumber:
 *                 type: string
 *                 maxLength: 18
 *               swiftBic:
 *                 type: string
 *                 pattern: '^[A-Z]{6}[A-Z2-9][A-NP-Z0-9]([A-Z0-9]{3})?$'
 *               beneficiaryIban:
 *                 type: string
 *                 maxLength: 34
 *               beneficiaryAddress:
 *                 type: string
 *                 maxLength: 70
 *               beneficiaryCity:
 *                 type: string
 *                 maxLength: 35
 *               beneficiaryPostalCode:
 *                 type: string
 *                 maxLength: 16
 *               beneficiaryCountry:
 *                 type: string
 *                 maxLength: 2
 *     responses:
 *       200:
 *         description: Beneficiary details updated successfully
 *       400:
 *         description: Validation failed or payment not in DRAFT status
 *       401:
 *         description: Authentication required
 */
router.put('/:id/beneficiary', 
  authenticateToken,
  requireCustomer,
  validateRequest(updateBeneficiarySchema),
  paymentController.updateBeneficiary.bind(paymentController)
);

/**
 * @swagger
 * /api/v1/payments/{id}/submit:
 *   post:
 *     summary: Submit payment for verification
 *     tags: [Payments]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: string
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - reference
 *               - purpose
 *             properties:
 *               reference:
 *                 type: string
 *                 maxLength: 35
 *               purpose:
 *                 type: string
 *                 maxLength: 140
 *               otp:
 *                 type: string
 *     responses:
 *       200:
 *         description: Payment submitted for verification successfully
 *       400:
 *         description: Validation failed or payment not in DRAFT status
 *       401:
 *         description: Authentication required
 */
router.post('/:id/submit', 
  authenticateToken,
  requireCustomer,
  validateRequest(submitPaymentSchema),
  paymentController.submitPayment.bind(paymentController)
);

/**
 * @swagger
 * /api/v1/payments/{id}/verify:
 *   post:
 *     summary: Verify payment (staff only)
 *     tags: [Payments]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: string
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - action
 *             properties:
 *               action:
 *                 type: string
 *                 enum: [approve, reject]
 *     responses:
 *       200:
 *         description: Payment verification completed successfully
 *       400:
 *         description: Validation failed or payment not in pending verification status
 *       401:
 *         description: Authentication required
 *       403:
 *         description: Staff access required
 */
router.post('/:id/verify',
  authenticateToken,
  paymentController.verifyPayment.bind(paymentController)
);

/**
 * @swagger
 * /api/v1/payments/{id}/submit-swift:
 *   post:
 *     summary: Submit verified payment to SWIFT (staff only)
 *     tags: [Payments]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: string
 *     responses:
 *       200:
 *         description: Payment submitted to SWIFT successfully
 *       400:
 *         description: Payment not in verified status
 *       401:
 *         description: Authentication required
 *       403:
 *         description: Staff access required
 */
router.post('/:id/submit-swift',
  authenticateToken,
  paymentController.submitToSwift.bind(paymentController)
);

/**
 * @swagger
 * /api/v1/payments/{id}:
 *   delete:
 *     summary: Delete a DRAFT payment
 *     tags: [Payments]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: string
 *     responses:
 *       204:
 *         description: Payment deleted successfully
 *       400:
 *         description: Payment not in DRAFT status
 *       401:
 *         description: Authentication required
 */
router.delete('/:id', 
  authenticateToken,
  requireCustomer,
  paymentController.deleteDraftPayment.bind(paymentController)
);

export default router;
