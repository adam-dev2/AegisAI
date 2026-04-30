import axios from "axios";
import { BASE_URL, BASE_URL_VERSION_2, EVIDENCE_URL, TENANT_API_KEY } from "../../config/env.js";


export const rapid7Client = axios.create({
    baseURL:BASE_URL!,
    headers:{
        'X-Api-Key':TENANT_API_KEY,
        'Content-Type':'application/json'
    },
    timeout:15000
})

export const rapid7ClientVersion2 = axios.create({
    baseURL:BASE_URL_VERSION_2!,
    headers:{
        'X-Api-Key':TENANT_API_KEY,
        'Content-Type':'application/json'
    },
    timeout:15000
})

export const rapid7ClientEvidence = axios.create({
    baseURL:EVIDENCE_URL!,
    headers:{
        'X-Api-Key':TENANT_API_KEY,
        'Content-Type':'application/json'
    },
    timeout:15000
})