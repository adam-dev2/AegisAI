import jwt, { type JwtPayload } from 'jsonwebtoken';
import { catchAsync } from '../lib/catchAsync.js';
import type { NextFunction, Request, Response } from 'express';
import { AppError } from '../lib/AppError.js';
import { API_KEY, JWT_SECRET } from '../config/env.js';
import type { loginTokenInterface,mfaTokenInterface } from '../types/token.interfaces.js';

declare module "express-serve-static-core" {
  interface Request {
    user?: IUser;
  }
}

interface IUser{
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
        const decoded = jwt.verify(token, JWT_SECRET!) as loginTokenInterface;
        if(!decoded.mfa_enabled) {
            throw new AppError("Invalid Token",401);
        }
        req.user = decoded as IUser;
        next();
    }catch(err:any) {
        if(err.name === "TokenExpiredError") {
            throw new AppError('Token Expired',401)
        }
        throw new AppError("Invalid Token",401);
    }
})

export const mfaVerifiedMiddleware = catchAsync(async(req:Request,res:Response,next:NextFunction) => {
    const authHeader = req.headers.authorization;
    const token = authHeader?.split('Bearer ')[1];
    if(!token) {
        throw new AppError("Token Missing",401);
    }
    try {
        const decoded = jwt.verify(token, JWT_SECRET!) as mfaTokenInterface;
        if(!decoded.mfa_verified) {
            throw new AppError("Invalid Token",401)
        }
        req.user = decoded as IUser;
        next();
    }catch(err:any) {
        if(err.name === "TokenExpiredError") {
            throw new AppError('Token Expired',401)
        }
        throw new AppError("Invalid Token",401);
    }
})

export const apiKeyVerify = catchAsync(async(req:Request,res:Response,next:NextFunction) => {
    const apiKeyHeader = req.headers.authorization;
    if(!apiKeyHeader) {
        throw new AppError("header not found",401);
    }
    const apiKey = apiKeyHeader.split('x-api-key ')[1];
    if(apiKey !== API_KEY) {
        throw new AppError("Invalid API Key",403);
    }

    res.status(200).json({success:true});
})