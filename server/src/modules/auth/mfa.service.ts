import type { Request} from "express";
import speakeasy from 'speakeasy'
import QRCode from 'qrcode'
import pool from "../../config/db.js";
import { AppError } from "../../lib/AppError.js";

export const mfaSetup = async(req:Request) => {
    const secret = speakeasy.generateSecret({
        name:req.user?.username
    })
    await pool.query("UPDATE users SET totp_secret = $1 WHERE email = $2",[secret,req.user?.email])
    const qr = await QRCode.toDataURL(secret.otpauth_url!);
    return qr
}

export const mfaVerify = async(req:Request) => {
    const gettotpSecret = await pool.query('SELECT totp_secret FROM users WHERE email=$1',[req.user?.email]);
    
}