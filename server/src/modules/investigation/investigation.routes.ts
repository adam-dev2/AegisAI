import express from 'express';
import { mfaVerifiedMiddleware } from '../../middleware/auth.middleware.js';
import {
    pollingStatus,
    startPolliing,
    stopPolliing,
    updatePollingInterval,
    agentHealth,
    runAgent,
} from './investigation.controllers.js';

const router = express.Router();

// router.use(mfaVerifiedMiddleware)

router.post('/polling/start', startPolliing)
router.post('/polling/stop', stopPolliing)
router.get('/polling/status', pollingStatus)
router.patch('/polling/interval', updatePollingInterval)
router.get('/agent/health', agentHealth)
router.post('/agent/run', runAgent)
// router.post('/:alertId/status')

export default router;