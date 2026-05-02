import type { Request, Response} from "express";
import speakeasy from 'speakeasy'
import QRCode from 'qrcode'
import pool from "../../config/db.js";
import { AppError } from "../../lib/AppError.js";
import jwt from 'jsonwebtoken'
import { JWT_SECRET, REFRESH_JWT_SECRET } from "../../config/env.js";
import { CookieOptions } from "../../types/CookieOptions.js";
import { catchAsync } from "../../lib/catchAsync.js";


export const mfaSetup = async(user:any) => {
    const secret = speakeasy.generateSecret({
        name: user.email
    })
    await pool.query("UPDATE users SET totp_secret = $1 WHERE email = $2",[secret.base32,user.email])
    const qr = await QRCode.toDataURL(secret.otpauth_url!);
    return qr
}
export const completedMFASetup = catchAsync(async(req:Request,res:Response) => {
    if(!req.user?.id) {
        throw new AppError("userid not found",401);
    }
    const userId = req.user.id;
    const updateUser = await pool.query('UPDATE users SET mfa_enabled = true WHERE id = $1',[userId]);

    if(!updateUser) {
        throw new AppError("Error while updating mfa enabled",500);
    }
    res.status(200).json({success:true})
})

export const mfaVerify = catchAsync(async(req:Request,res:Response) => {
    const authHeader = req.headers.authorization
    const token = authHeader?.split('Bearer ')[1];
    const otp = req.body.token;
    if(!token) {
        throw new AppError("Login Token missing",401);
    }
    const result = await pool.query('SELECT totp_secret, id, email FROM users WHERE email=$1',[req.user?.email]);

    const secret = result.rows[0]?.totp_secret;
    const user = result.rows[0];

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
        throw new AppError('Invalid MFA',401);
    }
    const generatToken = jwt.sign({
        id:user.id,
        username:user.email,
        email:user.email,
        mfa_verified:true
    },
    JWT_SECRET!,
    {expiresIn:'3h'}
    )
    const generateRefreshToken = jwt.sign({
        id:user.id,
        type:'refresh'
    },REFRESH_JWT_SECRET!,{expiresIn:'8h'})
    res.cookie('token',generatToken,CookieOptions)
    res.cookie('refreshToken',generateRefreshToken,CookieOptions)
    res.status(200).json({
        success:true,
        accessToken: generatToken,
        refreshToken: generateRefreshToken,
        user: {
            id: user.id,
            email: user.email,
            username: user.email
        }
    })
})