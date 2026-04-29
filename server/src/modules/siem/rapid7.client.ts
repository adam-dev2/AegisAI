import axios from "axios";
import { BASE_URL, TENANT_API_KEY } from "../../config/env.js";


export const rapid7Client = axios.create({
    baseURL:BASE_URL!,
    headers:{
        'X-Api-Key':TENANT_API_KEY,
        'Content-Type':'application/json'
    },
    timeout:15000
})