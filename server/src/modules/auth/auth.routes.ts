import express from 'express';
import { changePass, loginUser, register, validatePass } from './auth.controller.js';
import { mfaVerify } from './mfa.service.js';
import { refreshTokenHandler } from './auth.service.js';

const router = express.Router();

router.post('/login',loginUser);
router.post('/mfaverify',mfaVerify);
router.post('/refresh',refreshTokenHandler);
router.post('/verifypass',validatePass);
router.post('/changepass',changePass);
router.post('/registerUser',register);

export default router;