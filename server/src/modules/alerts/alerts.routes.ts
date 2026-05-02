import express from 'express';
import { mfaVerifiedMiddleware } from '../../middleware/auth.middleware.js';
import { getAlerts, getAlert, patchAlertStatus } from './alerts.controller.js';

const router = express.Router();

router.use(mfaVerifiedMiddleware);

router.get('/', getAlerts);
router.get('/:alertId', getAlert);
router.patch('/:alertId/status', patchAlertStatus);

export default router;
