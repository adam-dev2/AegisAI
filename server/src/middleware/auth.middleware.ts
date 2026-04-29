import jwt, { type JwtPayload } from 'jsonwebtoken';
import { catchAsync } from '../lib/catchAsync.js';
import type { NextFunction, Request, Response } from 'express';
import { AppError } from '../lib/AppError.js';
import { JWT_SECRET } from '../config/env.js';

declare module "express-serve-static-core" {
  interface Request {
    user?: IUser;
  }
}

interface IUser {
    id:string,
    username:string,
    email:string
}

export const authMiddleware = catchAsync(async(req:Request,res:Response,next:NextFunction) => {
    const authHeader = req.headers.authorization;
    const token = authHeader?.split('Bearer ')[1];
    if(!token) {
        throw new AppError("Token Missing",401);
    }
    try {
        const decoded = jwt.verify(token, JWT_SECRET!) as JwtPayload;
        req.user = decoded as IUser;
        next();
    }catch(err:any) {
        if(err.name === "TokenExpiredError") {
            throw new AppError('Token Expired',401)
        }
        throw new AppError("Invalid Token",401);
    }
})