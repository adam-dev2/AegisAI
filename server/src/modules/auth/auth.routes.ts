import express from 'express';
import { changePass, loginUser, register, validatePass } from './auth.controller.js';
import { completedMFASetup, mfaVerify } from './mfa.service.js';
import { refreshTokenHandler } from './auth.service.js';
import { apiKeyVerify, authMiddleware, mfaVerifiedMiddleware } from '../../middleware/auth.middleware.js';

const router = express.Router();

router.post('/login',loginUser);
router.post('/mfa-setup',authMiddleware,completedMFASetup);
router.post('/mfaverify',authMiddleware,mfaVerify);
router.post('/refresh',mfaVerifiedMiddleware,refreshTokenHandler);
router.post('/verifypass',mfaVerifiedMiddleware,validatePass);
router.post('/changepass',mfaVerifiedMiddleware,changePass);
router.post('/registerUser',apiKeyVerify,register);

export default router;