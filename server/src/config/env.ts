import 'dotenv/config'

export const PORT = process.env.PORT || 5000
export const DATABASE_URL = process.env.DATABASE_URL
export const JWT_SECRET = process.env.JWT_SECRET
export const NODE_ENV = process.env.NODE_ENV
export const REFRESH_JWT_SECRET = process.env.REFRESH_JWT_SECRET
export const API_KEY = process.env.API_KEY 
export const BASE_URL = process.env.BASE_URL
export const REGION = process.env.REGION
export const TENANT_API_KEY = process.env.TENANT_API_KEY
export const BASE_URL_VERSION_2 = process.env.BASE_URL_VERSION_2
export const EVIDENCE_URL = process.env.EVIDENCE_URL
export const ANTHROPIC_API_KEY = process.env.ANTHROPIC_API_KEY
export const ANTHROPIC_MODEL = process.env.ANTHROPIC_MODEL || 'claude-3.5-mini'
export const ANTHROPIC_API_URL = process.env.ANTHROPIC_API_URL || 'https://api.anthropic.com/v1/chat/completions'