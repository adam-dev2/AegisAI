import type { Request, Response } from "express";
import { catchAsync } from "../../lib/catchAsync.js";
import { AppError } from "../../lib/AppError.js";
import { pollingManger } from "../../jobs/pollingManager.js";
import { runAgentAnalysis } from "./ai.agent.js";

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
    const { newInterval } = req.body;
    const minInterval = Math.max(60 * 1000, Number(newInterval) || 60 * 1000);
    pollingManger.updateInterval(minInterval);
    res.status(200).json({
        success:true,
        message:'polling interval updated',
        intervalMs: minInterval,
    });
});

export const agentHealth = catchAsync(async (req: Request, res: Response) => {
    res.status(200).json({ success: true, available: true, anthropic_enabled: Boolean(process.env.ANTHROPIC_API_KEY) });
});

export const runAgent = catchAsync(async(req:Request,res:Response) => {
    const { investigation_id, investigation_context, question, max_steps } = req.body;

    if (!question || typeof question !== 'string') {
        throw new AppError('question is required and must be a string', 400);
    }

    const agentResult = await runAgentAnalysis({
        investigation_id,
        investigation_context,
        question,
        max_steps: Number(max_steps) || 3,
    });

    res.status(200).json({
        success: true,
        data: agentResult,
    });
});
