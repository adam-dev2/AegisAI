import express from 'express';
import { mfaVerifiedMiddleware } from '../../middleware/auth.middleware.js';

const router = express.Router();

router.use(mfaVerifiedMiddleware)

// router.get('/')
// router.get('/:id')
// router.get('/status/:status')
// router.patch('/:id/status')

export default router;