import type { Request, Response } from "express";
import { catchAsync } from "../../lib/catchAsync.js";
import { pollingManger } from "../../jobs/pollingManager.js";

export const startPolliing = catchAsync(async(req:Request,res:Response) => {
    pollingManger.start();
    res.status(200).json({
        success:true,
        message:'polling started'
    })
})

export const stopPolliing = catchAsync(async(req:Request,res:Response) => {
    pollingManger.stop();
    res.status(200).json({
        success:true,
        message:'polling stopped'
    })
})

export const pollingStatus = catchAsync(async(req:Request,res:Response) => {
    const status = pollingManger.getStatus();
    res.status(200).json({
        success:true,
        status
    })
})

export const updatePollingInterval = catchAsync(async(req:Request,res:Response) => {
    const {newInterval} = req.body;
    const minInterval = Math.min(60*1000,newInterval);
    pollingManger.updateInterval(minInterval)
    res.status(200).json({
        success:true,
        message:'polling Interval updated'
    })
})
