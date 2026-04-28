import type { Request, Response } from "express";
import { catchAsync } from "../../lib/catchAsync.js";
import { AppError } from "../../lib/AppError.js";
import jwt, { type JwtPayload } from 'jsonwebtoken'
import { JWT_SECRET, NODE_ENV } from "../../config/env.js";
import type { ICookieOptions } from "./auth.controller.js";

export const refreshTokenHandler = catchAsync(async(req:Request,res:Response) => {
   const currentRefreshToken = req.cookies.refreshToken;
   if(!currentRefreshToken) {
        throw new AppError("Refresh token missing",403);
   }
   try {
    const decoded = jwt.verify(currentRefreshToken,JWT_SECRET!) as JwtPayload;
   }catch(err:any) {
    if(err.name = "TokenExpiredError"){
        throw new AppError("refresh token expired please login again",403)
    }
    throw new AppError("Invalid refresh token",403)
   }

   const newAccessToken = jwt.sign({id:req.user?.id, email:req.user?.email},JWT_SECRET!,{expiresIn:'8h'})
   const CookieOptions:ICookieOptions = {
        httpOnly:true,
        secure:NODE_ENV === 'production',
        sameSite:'lax',
        maxAge:60*100*100
    }
    res.cookie('token',newAccessToken,CookieOptions);
    res.status(200).json({success:true,newToken:newAccessToken});
})