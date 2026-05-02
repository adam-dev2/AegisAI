import { rapid7ClientVersion2 } from '../siem/rapid7.client.js';
import { logger } from '../../lib/logger.js';

export interface EnrichmentContext {
  investigation_id: string;
  user_data?: any[];
  asset_data?: any[];
  threat_intel?: any[];
  risk_scores?: Record<string, number>;
}

export async function enrichUserData(usernames: string[]): Promise<any[]> {
  try {
    const uniqueUsers = Array.from(new Set(usernames)).filter(Boolean);

    if (uniqueUsers.length === 0) return [];

    const enrichedUsers = await Promise.all(
      uniqueUsers.map(async (username) => {
        try {
          const res = await rapid7ClientVersion2.get('/users', {
            params: { search: username, size: 1 },
          });
          return res.data?.data?.[0] || null;
        } catch (err: any) {
          logger.warn(`Failed to enrich user ${username}:`, err.message);
          return null;
        }
      })
    );

    return enrichedUsers.filter(Boolean);
  } catch (err: any) {
    logger.error('User enrichment failed:', err.message);
    return [];
  }
}

export async function enrichAssetData(hostnames: string[]): Promise<any[]> {
  try {
    const uniqueAssets = Array.from(new Set(hostnames)).filter(Boolean);

    if (uniqueAssets.length === 0) return [];

    const enrichedAssets = await Promise.all(
      uniqueAssets.map(async (hostname) => {
        try {
          const res = await rapid7ClientVersion2.get('/assets', {
            params: { search: hostname, size: 1 },
          });
          return res.data?.data?.[0] || null;
        } catch (err: any) {
          logger.warn(`Failed to enrich asset ${hostname}:`, err.message);
          return null;
        }
      })
    );

    return enrichedAssets.filter(Boolean);
  } catch (err: any) {
    logger.error('Asset enrichment failed:', err.message);
    return [];
  }
}

export async function calculateRiskScores(actors: {
  users: string[];
  ips: string[];
  assets: string[];
}): Promise<Record<string, number>> {
  const scores: Record<string, number> = {};

  try {
    // Base score for each actor type
    actors.users.forEach((user) => {
      scores[`user:${user}`] = 0.3; // Neutral base score
    });

    actors.ips.forEach((ip) => {
      scores[`ip:${ip}`] = 0.4; // Slightly higher for external IPs
    });

    actors.assets.forEach((asset) => {
      scores[`asset:${asset}`] = 0.3; // Neutral base score
    });

    return scores;
  } catch (err: any) {
    logger.error('Risk score calculation failed:', err.message);
    return scores;
  }
}

export async function enrichInvestigation(investigationId: string, context: any): Promise<EnrichmentContext> {
  logger.info(`Enriching investigation ${investigationId}`);

  const users = new Set<string>();
  const assets = new Set<string>();

  // Extract actors from alerts
  context.alerts?.forEach((alert: any) => {
    alert.evidences?.forEach((evidence: any) => {
      if (evidence.actor?.user) users.add(evidence.actor.user);
      if (evidence.actor?.asset) assets.add(evidence.actor.asset);
    });
  });

  const userArray = Array.from(users);
  const assetArray = Array.from(assets);

  const [enrichedUsers, enrichedAssets, riskScores] = await Promise.all([
    enrichUserData(userArray),
    enrichAssetData(assetArray),
    calculateRiskScores({
      users: userArray,
      ips: [],
      assets: assetArray,
    }),
  ]);

  logger.info(`Investigation ${investigationId} enriched with ${enrichedUsers.length} users and ${enrichedAssets.length} assets`);

  return {
    investigation_id: investigationId,
    user_data: enrichedUsers,
    asset_data: enrichedAssets,
    threat_intel: [],
    risk_scores: riskScores,
  };
}
