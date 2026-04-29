import express from 'express';
import { mfaVerifiedMiddleware } from '../../middleware/auth.middleware.js';
import { createConnection, fetchConnections } from './siem.controller.js';

const router = express.Router();

router.use(mfaVerifiedMiddleware)

router.get('/connection',fetchConnections)
router.post('/connection',createConnection)
// router.put('/connection')
// router.delete('/connection')
// router.get('/connection/status')
// router.post('/connection/test')

export default router;