import { logger } from "../lib/logger.js";
import { rapid7Client } from "../modules/siem/rapid7.client.js";
import type { PollingState } from "../types/pollingstate.js";
import { DateTime } from 'luxon'
import fs from 'fs'
import { processInvestigation } from "../modules/investigation/investigation.services.js";
import { queryLogs } from "../tools/queryRapid7.js";

class pollingManager {
    private state: PollingState = {
        isRunning:false,
        intervalMs:20*1000,
        timer:null
    }
    private async pollTask() {
        const currentTime = DateTime.now()
            .setZone('America/Godthab')
            .minus({ days: 1 })
            .toFormat("yyyy-MM-dd'T'HH:mm:ss.000'Z'");
        try {
            logger.info('Polling rapid7 API');
            const response = await rapid7Client.get(`/investigations?start_time=${currentTime}`)
            const data = response.data;
            logger.info(data)
            fs.writeFileSync('responseData.json',JSON.stringify(response.data))
            logger.info(data.length)

            if(data.data.length !== 0 ){
                await processInvestigation(data.data);
            }
            const result = await queryLogs(
                "5a1e9e6c-53d1-493a-91f8-78deda2fe3c9",
                'where(log_entry_id = "4cfcf15d-ad22-4972-a10b-31392122d9f4") limit(1000)',
                'Last 2h'
            );
            fs.writeFileSync("logs.json",JSON.stringify(result,null,2))
        }catch(err) {
            logger.error('Polling Failed',err)
        }
    }
    start() {
        if (this.state.isRunning) return;
        this.state.isRunning = true;

        const run = async () => {
            if (!this.state.isRunning) return;
            try {
                await this.pollTask();
            } catch (err) {
                console.error("Polling error:", err);
            }
            if (this.state.isRunning) {
                this.state.timer = setTimeout(run, this.state.intervalMs);
            }
        };
        run();
    }
    stop() {
        if(this.state.isRunning) {
            clearInterval(this.state.timer!)
            this.state.timer = null;
        }
        
        this.state.isRunning = false;
    }
    updateInterval(newInterval:number) {
        this.state.intervalMs = newInterval;

        if(this.state.isRunning) {
            this.stop();
            this.start();
        }
    }
    getStatus():{} {
        return {
            status:this.state.isRunning,
            intervalMs:this.state.intervalMs
        }
    }

}

export const pollingManger = new pollingManager();