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
import { logger } from "../../lib/logger.js";

export const register = catchAsync(async (req: Request, res: Response) => {
  const { email, password } = req.body;
  if (!email || !password) {
    throw new AppError("Email and password are required", 400);
  }
  if (password.length < 8) {
    throw new AppError("Password must be atleast 8 character long", 400);
  }
  const existingUser = await pool.query(
    "SELECT id FROM users WHERE email = $1",
    [email],
  );
  if (existingUser.rowCount && existingUser.rowCount > 0) {
    throw new AppError("User with this email already exists", 409);
  }
  const saltRounds = 12;
  const passwordHash = await bcrypt.hash(password, saltRounds);
  const result = await pool.query(
    `INSERT INTO users(email,password_hash) VALUES($1,$2) RETURNING id,email`,
    [email, passwordHash],
  );
  const newUser = result.rows[0];
  res.status(201).json({
    success: true,
    message: "User registered successfully",
    data: {
      id: newUser.id,
      email: newUser.email,
    },
  });
});

export const loginUser = catchAsync(async (req: Request, res: Response) => {
  const { email, password } = req.body;
  if (!email || !password) {
    throw new AppError("Email and password required", 400);
  }
  const result = await pool.query(
    "SELECT id, email, password_hash FROM users WHERE email = $1",
    [email],
  );
  if (result.rowCount === 0) {
    throw new AppError("Invalid credentials", 401);
  }
  const user = result.rows[0];
  const isMatch = await bcrypt.compare(password, user.password_hash);
  if (!isMatch) {
    throw new AppError("Invalid credentials", 401);
  }

  const generateToken = jwt.sign(
    {
      id: user.id,
      username: user.username,
      email: user.email,
      mfa_enabled: user.mfa_enabled,
    },
    JWT_SECRET!,
    {
      expiresIn: "5m",
    },
  );
  let qr;
  if (!user.mfa_enabled) {
    try {
      qr = await mfaSetup(req);
    } catch (err) {
      throw new AppError("Erro while generating qr", 500);
    }
  }
  logger.info(qr)
  res.cookie("token", generateToken, CookieOptions);
  res.status(200).json({
    success: true,
    mfa_setup: !user.mfa_enabled,
    qr,
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

  const verify = bcrypt.compare(oldPassword, fetchUser.rows[0].password_hash);
  if (!verify) {
    throw new AppError("Invalid Credentials", 400);
  }

  res.status(200).json({ success: true });
});

export const changePass = catchAsync(async (req: Request, res: Response) => {
  const { oldPassword, newPassword, otp } = req.body;
  if (!otp) {
    throw new AppError("MFA missing", 400);
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
  const verify = bcrypt.compare(oldPassword, fetchUser.rows[0].password_hash);
  if (!verify) {
    throw new AppError("Invalid Credentials", 400);
  }
  const secret = fetchUser.rows[0].totp_secret;
  const verified = speakeasy.totp.verify({
    secret,
    encoding: "base32",
    token: otp,
    window: 1,
  });
  if (!verified) {
    throw new AppError("Invalid MFA", 401);
  }
  const newPasswordHash = await bcrypt.hash(newPassword, 12);
  const updatePassword = await pool.query(
    "UPDATE users SET password_hash = $1 WHERE id=$2",
    [newPasswordHash, req.user?.id],
  );
  if (!updatePassword) {
    throw new AppError("Error while update password", 500);
  }
  res
    .status(200)
    .json({ success: true, message: "password updated successfully" });
});
