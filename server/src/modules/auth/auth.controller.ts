import type { Request, Response } from "express";
import { catchAsync } from "../../lib/catchAsync.js";
import { AppError } from "../../lib/AppError.js";
import pool from '../../config/db.js';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken'
import { JWT_SECRET, NODE_ENV } from "../../config/env.js";
import { mfaSetup } from "./mfa.service.js";
import { CookieOptions } from "../../lib/CookieOptions.js";

export const loginUser = catchAsync(async (req: Request, res: Response) => {
  const { email, password } = req.body;
  if (!email || !password) {
    throw new AppError("Email and password required", 400);
  }
  const result = await pool.query(
    'SELECT id, email, password_hash FROM users WHERE email = $1',
    [email]
  );
  if (result.rowCount === 0) {
    throw new AppError("Invalid credentials", 401);
  }
  const user = result.rows[0];
  const isMatch = await bcrypt.compare(password, user.password_hash);
  if (!isMatch) {
    throw new AppError("Invalid credentials", 401);
  }
  
  const generateToken = jwt.sign({ id: user.id,username:user.username, email: user.email,mfa_enabled:user.mfa_enabled },JWT_SECRET!,{
    expiresIn: '5m'
  })
  let qr;
  if(!user.mfa_enabled){
    try {
        qr = mfaSetup(req)
    }catch(err) {
        throw new AppError("Erro while generating qr",500)
    }
  }

  res.cookie('token',generateToken,CookieOptions);
  res.status(200).json({
    success: true,
    data: { id: user.id, email: user.email },
    mfa_setup:!user.mfa_enabled,
    qr
  });
});