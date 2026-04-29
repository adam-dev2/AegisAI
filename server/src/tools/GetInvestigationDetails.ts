import { logger } from "../lib/logger.js";
import { rapid7Client } from "../modules/siem/rapid7.client.js"
import fs from 'fs'

export const fetchFullInvestigation = async(id:string) =>{
    if(!id) {
        return;
    }
    logger.info('InvestigationI:',id)
    try{
        const response = await rapid7Client.get(`/${id}`);
        logger.info(response.data)
        fs.writeFileSync('detailInvestigation.json',JSON.stringify(response.data));
    }catch(err:any) {
        logger.error('Error while Fetching detail Investigation',err)
    }
    
}