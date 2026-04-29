import { NODE_ENV } from "../config/env.js"

export interface ICookieOptions {
    httpOnly:boolean,
    secure:boolean,
    sameSite:boolean | "lax" | "strict" | "none" | undefined,
    maxAge:number
}

export const CookieOptions:ICookieOptions = {
    httpOnly:true,
    secure:NODE_ENV === 'production',
    sameSite:'lax',
    maxAge:60 * 60 * 1000
}