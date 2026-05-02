import pool from '../../config/db.js';

export interface FeedbackInput {
  investigation_id: string;
  rating: 1 | 2 | 3 | 4 | 5;
  comment?: string;
}

export async function submitFeedback(userId: string, feedback: FeedbackInput) {
  const result = await pool.query(
    'INSERT INTO feedback(user_id, investigation_id, rating, comment, created_at) VALUES($1,$2,$3,$4,$5) RETURNING *',
    [userId, feedback.investigation_id, feedback.rating, feedback.comment || null, new Date().toISOString()]
  );
  return result.rows[0];
}

export async function getFeedbackByInvestigation(investigationId: string) {
  const result = await pool.query(
    'SELECT id, user_id, investigation_id, rating, comment, created_at FROM feedback WHERE investigation_id = $1 ORDER BY created_at DESC',
    [investigationId]
  );
  return result.rows;
}

export async function getFeedbackStats(investigationId: string) {
  const result = await pool.query(
    'SELECT COUNT(*) as total, AVG(rating) as avg_rating, SUM(CASE WHEN rating >= 4 THEN 1 ELSE 0 END) as positive_count FROM feedback WHERE investigation_id = $1',
    [investigationId]
  );
  const row = result.rows[0];
  return {
    total_feedback: Number(row.total),
    average_rating: row.avg_rating ? parseFloat(row.avg_rating) : 0,
    positive_count: Number(row.positive_count),
  };
}
