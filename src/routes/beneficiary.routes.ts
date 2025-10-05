import { Router } from 'express';
import { beneficiaryController } from '@/controllers/beneficiary.controller';
import { authenticateToken } from '@/middleware/auth.middleware';
import { validateRequest } from '@/middleware/validation.middleware';
import { 
  createBeneficiarySchema
} from '@/validators/beneficiary.validators';

// Task 2 Compliant: Beneficiary routes
const router = Router();

/**
 * @swagger
 * /api/v1/beneficiaries:
 *   get:
 *     summary: Get user's beneficiaries
 *     tags: [Beneficiaries]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: Beneficiaries retrieved successfully
 *       401:
 *         description: Authentication required
 */
router.get('/', 
  authenticateToken,
  beneficiaryController.getUserBeneficiaries.bind(beneficiaryController)
);

/**
 * @swagger
 * /api/v1/beneficiaries:
 *   post:
 *     summary: Create a new beneficiary
 *     tags: [Beneficiaries]
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - fullName
 *               - bankName
 *               - accountNumber
 *               - swiftCode
 *             properties:
 *               fullName:
 *                 type: string
 *                 description: Full name of the beneficiary
 *               bankName:
 *                 type: string
 *                 description: Bank name
 *               accountNumber:
 *                 type: string
 *                 description: Account number
 *               swiftCode:
 *                 type: string
 *                 description: SWIFT/BIC code
 *     responses:
 *       201:
 *         description: Beneficiary created successfully
 *       400:
 *         description: Validation failed
 *       401:
 *         description: Authentication required
 */
router.post('/',
  authenticateToken,
  validateRequest(createBeneficiarySchema),
  beneficiaryController.createBeneficiary.bind(beneficiaryController)
);

/**
 * @swagger
 * /api/v1/beneficiaries/{id}:
 *   delete:
 *     summary: Delete a beneficiary
 *     tags: [Beneficiaries]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: string
 *         description: Beneficiary ID
 *     responses:
 *       200:
 *         description: Beneficiary deleted successfully
 *       401:
 *         description: Authentication required
 *       404:
 *         description: Beneficiary not found
 */
router.delete('/:id',
  authenticateToken,
  beneficiaryController.deleteBeneficiary.bind(beneficiaryController)
);

export default router;

