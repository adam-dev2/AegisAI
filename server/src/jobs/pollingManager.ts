import { INVESTIGATION_URL, TENANT_API_KEY } from "../config/env.js";
import { logger } from "../lib/logger.js";
import { parseInvestigationDetails } from "../tools/ParseInvestigation.js";
import type { PollingState } from "../types/pollingstate.js";
import axios from 'axios'
import { DateTime } from 'luxon'

class pollingManager {
    private state: PollingState = {
        isRunning:false,
        intervalMs:1*60*1000,
        timer:null
    }
    private async pollTask() {
        const currentTime = DateTime.now().setZone('America/Godthab').toFormat("yyyy-MM-dd'T'HH:mm:ss.000'Z'");
        try {
            logger.info('Polling rapid7 API');
            const response = await axios.get(`${INVESTIGATION_URL}?statuses=open&start_time=${currentTime}`,{
                headers:{
                    "x-api-key":TENANT_API_KEY,
                    "Content-Type":'application/json'
                }
            })
            const data = response.data;
            logger.info(data.length)
            if(data.data.length !== 0 ){
                parseInvestigationDetails(data.data);
            }
            
        }catch(err) {
            logger.error('Polling Failed',err)
        }
    }
    start() {
        if(this.state.isRunning) {
            return;
        }
        this.state.timer = setInterval(() => {
            this.pollTask()
        },this.state.intervalMs);
        
        this.state.isRunning = true
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