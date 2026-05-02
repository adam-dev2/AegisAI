import express from 'express';
import { mfaVerifiedMiddleware } from '../../middleware/auth.middleware.js';
import { createConnection, fetchConnections, updateConnection } from './siem.controller.js';

const router = express.Router();

router.use(mfaVerifiedMiddleware);

router.get('/connection', fetchConnections);
router.post('/connection', createConnection);
router.patch('/connection', updateConnection);

export default router;
