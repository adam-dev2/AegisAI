import type { Request, Response } from "express";
import { catchAsync } from "../../lib/catchAsync.js";
import { AppError } from "../../lib/AppError.js";
import pool from "../../config/db.js";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import { JWT_SECRET } from "../../config/env.js";
import { mfaSetup } from "./mfa.service.js";
import { CookieOptions } from "../../types/CookieOptions.js";
import speakeasy from "speakeasy";

export const register = catchAsync(async (req: Request, res: Response) => {
  const { username, email, password } = req.body;

  if (!username || !email || !password) {
    throw new AppError("All fields are required", 400);
  }

  if (password.length < 8) {
    throw new AppError("Password must be at least 8 characters", 400);
  }

  const existingUser = await pool.query(
    "SELECT id FROM users WHERE email = $1",
    [email]
  );

  if (existingUser.rowCount) {
    throw new AppError("User already exists", 409);
  }

  const passwordHash = await bcrypt.hash(password, 12);

  const result = await pool.query(
    `INSERT INTO users(username, email, password_hash)
     VALUES($1,$2,$3)
     RETURNING id, username, email`,
    [username, email, passwordHash]
  );

  res.status(201).json({
    success: true,
    data: result.rows[0],
  });
});

export const loginUser = catchAsync(async (req: Request, res: Response) => {
  const { email, password } = req.body;

  if (!email || !password) {
    throw new AppError("Email & password required", 400);
  }

  const result = await pool.query(
    `SELECT id, email, password_hash, mfa_enabled 
     FROM users WHERE email = $1`,
    [email]
  );

  if (!result.rowCount) {
    throw new AppError("Invalid credentials", 401);
  }

  const user = result.rows[0];

  const isMatch = await bcrypt.compare(password, user.password_hash);
  if (!isMatch) {
    throw new AppError("Invalid credentials", 401);
  }

  // 🔹 STEP 1: MFA not enabled → setup
  if (!user.mfa_enabled) {
    const qr = await mfaSetup(user);

    const token = jwt.sign(
      { id: user.id, mfa_setup: true },
      JWT_SECRET!,
      { expiresIn: "10m" }
    );

    res.cookie("token", token, CookieOptions);

    res.json({
      success: true,
      mfaRequired: "setup",
      qr,
    });
  }

  const token = jwt.sign(
    { id: user.id, mfa_verified: false },
    JWT_SECRET!,
    { expiresIn: "5m" }
  );

  res.cookie("token", token, CookieOptions);

  res.json({
    success: true,
    mfaRequired: "verify",
  });
});

export const validatePass = catchAsync(async (req: Request, res: Response) => {
  const { oldPassword, newPassword } = req.body;
  if (!oldPassword || !newPassword) {
    throw new AppError("both fields are required", 400);
  }
  if (oldPassword === newPassword) {
    throw new AppError("old and new password can't be same", 400);
  }
  const fetchUser = await pool.query(
    "SELECT password_hash FROM users WHERE email = $1 AND id = $2",
    [req.user?.email, req.user?.id],
  );
  if (fetchUser.rowCount === 0) {
    throw new AppError("UnAuthorized", 403);
  }

  const verify = await bcrypt.compare(oldPassword, fetchUser.rows[0].password_hash);
  if (!verify) {
    throw new AppError("Invalid Credentials", 400);
  }

  res.status(200).json({ success: true });
});

export const changePass = catchAsync(async (req: Request, res: Response) => {
  const { oldPassword, newPassword, otp } = req.body;

  if (!oldPassword || !newPassword || !otp) {
    throw new AppError("All fields required", 400);
  }

  if (newPassword.length < 8) {
    throw new AppError("Password must be at least 8 chars", 400);
  }

  if (oldPassword === newPassword) {
    throw new AppError("New password must be different", 400);
  }

  const userRes = await pool.query(
    `SELECT password_hash, totp_secret 
     FROM users WHERE id = $1`,
    [req.user?.id]
  );

  if (!userRes.rowCount) {
    throw new AppError("Unauthorized", 403);
  }

  const user = userRes.rows[0];

  const validPass = await bcrypt.compare(oldPassword, user.password_hash);
  if (!validPass) {
    throw new AppError("Invalid credentials", 401);
  }

  const isOtpValid = speakeasy.totp.verify({
    secret: user.totp_secret,
    encoding: "base32",
    token: otp,
    window: 1,
  });

  if (!isOtpValid) {
    throw new AppError("Invalid OTP", 401);
  }

  const newHash = await bcrypt.hash(newPassword, 12);

  await pool.query(
    "UPDATE users SET password_hash = $1 WHERE id = $2",
    [newHash, req.user?.id]
  );

  res.json({
    success: true,
    message: "Password updated",
  });
});
