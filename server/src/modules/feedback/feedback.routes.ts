import express from 'express';
import { mfaVerifiedMiddleware } from '../../middleware/auth.middleware.js';
import { postFeedback, getFeedback, getFeedbackStats } from './feedback.controller.js';

const router = express.Router();

router.use(mfaVerifiedMiddleware);

router.post('/', postFeedback);
router.get('/:investigation_id', getFeedback);
router.get('/:investigation_id/stats', getFeedbackStats);

export default router;
