import express from 'express';
import { mfaVerifiedMiddleware } from '../../middleware/auth.middleware.js';
import { getInvestigationReport, getAlertReport } from './report.controller.js';

const router = express.Router();

router.use(mfaVerifiedMiddleware);

router.get('/investigation/:investigation_id', getInvestigationReport);
router.get('/alert/:alert_id', getAlertReport);

export default router;
