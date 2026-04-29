import type { Request, Response } from "express";
import { catchAsync } from "../../lib/catchAsync.js";
import { AppError } from "../../lib/AppError.js";
import pool from "../../config/db.js";

export const createConnection = catchAsync(async(req:Request,res:Response) => {
    const {region,apikey,console} = req.body;
    const userId = req.user?.id;
    if(!region || !apikey || !console) {
        throw new AppError("both region and api key are required",400);
    }
    if(!userId) {
        throw new AppError("unAuthorized",403);
    }
    const addConnection = await pool.query('INSERT INTO siem_connections(user_id,provider,api_key_enc,region,is_active,connected_at) VALUES($1,$2,$3,$4,$5,$6)',
    [userId,console,apikey,region,true,Date.now().toLocaleString])

    if(addConnection.rowCount === 0) {
        throw new AppError("Error while adding conneciton",500);
    }

    res.status(200).json({succes:true, message:`added ${console} to the dashboard`})
})


export const fetchConnections = catchAsync(async(req:Request,res:Response) => {
    const userId = req.user?.id;
    if(!userId) {
        throw new AppError("UnAuthorized",403);
    }

    const connections = await pool.query('SELECT provider,is_active,connected_at FROM siem_connections WHERE user_id = $1',[userId]);

    res.status(200).json({
        success:true,
        TotalConnections:connections.rowCount,
        connections
    })
})


/// THIS IS IN PROGRESS NEED TO FIGURE THIS OUT LATER
export const updateConnection = catchAsync(async(req:Request,res:Response) => {
    const {connectionId,apikey,provider,region} = req.body;
    if(!connectionId) {
        throw new AppError("connection Id missing",400);
    }
    if(!apikey && !provider && !region) {
        throw new AppError("all fields are empty not sure what to update",400);
    }
    const userId = req.user?.id;
    if(!userId) {
        throw new AppError("unAuthorized",403);
    }
    
})