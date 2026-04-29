import type { Request, Response, NextFunction } from "express";
import { AppError } from "../lib/AppError.js";

export const errorHandler = (err: any, req: Request, res: Response, next: NextFunction) => {
  const status = err.statusCode || 500;
  const message = err.message || "Internal server error";
  res.status(status).json({ success: false, error: { message } });
};