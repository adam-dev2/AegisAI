import pool from '../../config/db.js';

export async function createSIEMConnection(
  userId: string,
  provider: string,
  apiKey: string,
  region: string
) {
  const result = await pool.query(
    'INSERT INTO siem_connections(user_id, provider, api_key_enc, region, is_active, connected_at) VALUES($1,$2,$3,$4,$5,$6) RETURNING *',
    [userId, provider, apiKey, region, true, new Date().toISOString()]
  );
  return result.rows[0];
}

export async function fetchSIEMConnections(userId: string) {
  const result = await pool.query(
    'SELECT id, provider, region, is_active, connected_at FROM siem_connections WHERE user_id = $1 ORDER BY connected_at DESC',
    [userId]
  );
  return result.rows;
}

export async function updateSIEMConnection(
  userId: string,
  connectionId: string,
  updates: {
    provider?: string;
    apiKey?: string;
    region?: string;
    is_active?: boolean;
  }
) {
  const fields: string[] = [];
  const values: any[] = [userId, connectionId];
  let idx = 3;

  if (updates.provider) {
    fields.push(`provider=$${idx++}`);
    values.push(updates.provider);
  }
  if (updates.apiKey) {
    fields.push(`api_key_enc=$${idx++}`);
    values.push(updates.apiKey);
  }
  if (updates.region) {
    fields.push(`region=$${idx++}`);
    values.push(updates.region);
  }
  if (typeof updates.is_active === 'boolean') {
    fields.push(`is_active=$${idx++}`);
    values.push(updates.is_active);
  }

  if (fields.length === 0) {
    throw new Error('No fields were provided to update');
  }

  const query = `UPDATE siem_connections SET ${fields.join(', ')} WHERE user_id=$1 AND id=$2 RETURNING id, provider, region, is_active, connected_at`;
  const result = await pool.query(query, values);

  if (result.rowCount === 0) {
    throw new Error('Connection not found or unauthorized');
  }

  return result.rows[0];
}
