import type { Request, Response} from "express";
import speakeasy from 'speakeasy'
import QRCode from 'qrcode'
import pool from "../../config/db.js";
import { AppError } from "../../lib/AppError.js";
import jwt, { type JwtPayload } from 'jsonwebtoken'
import { JWT_SECRET, REFRESH_JWT_SECRET } from "../../config/env.js";
import { CookieOptions } from "../../lib/CookieOptions.js";


export const mfaSetup = async(req:Request) => {
    const secret = speakeasy.generateSecret({
        name:req.user?.username
    })
    await pool.query("UPDATE users SET totp_secret = $1 WHERE email = $2",[secret.base32,req.user?.email])
    const qr = await QRCode.toDataURL(secret.otpauth_url!);
    return qr
}

export const mfaVerify = async(req:Request,res:Response) => {
    const authHeader = req.headers.authorization
    const token = authHeader?.split('Bearer ')[1];
    const otp = req.body.otp;
    if(!token) {
        throw new AppError("Login Token missing",401);
    }
    const result = await pool.query('SELECT totp_secret FROM users WHERE email=$1',[req.user?.email]);

    const secret = result.rows[0]?.totp_secret;

    if(!secret) {
        throw new AppError("MFA Not Setup",400);
    }
    const verified = speakeasy.totp.verify({
        secret,
        encoding:'base32',
        token:otp,
        window:1
    })
    if(!verified) {
        throw new AppError('Invalid MFA Token',401);
    }
    const generatToken = jwt.sign({
        id:req.user?.id,
        username:req.user?.username,
        email:req.user?.email,
        mfa_verified:true
    },
    JWT_SECRET!,
    {expiresIn:'3h'}
    )
    const generateRefreshToken = jwt.sign({
        id:req.user?.id,
        type:'refresh'
    },REFRESH_JWT_SECRET!,{expiresIn:'8h'})
    res.cookie('token',generatToken,CookieOptions)
    res.cookie('refreshToken',generateRefreshToken,CookieOptions)
    res.status(200).json({success:true})
}