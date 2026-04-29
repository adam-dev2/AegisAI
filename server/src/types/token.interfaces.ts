import type { JwtPayload } from "jsonwebtoken";

export interface loginTokenInterface extends JwtPayload {
    id:string,
    username:string,
    email:string,
    mfa_enabled:boolean
}

export interface mfaTokenInterface extends JwtPayload {
    id:string,
    username:string,
    email:string,
    mfa_verified:boolean
}