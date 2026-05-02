import { logger } from '../lib/logger.js';

// Job queue interface - ready for BullMQ or similar integration
// Currently using in-memory storage, but can be replaced with Redis-backed queue

interface QueuedJob {
  id: string;
  type: string;
  data: any;
  status: 'pending' | 'processing' | 'completed' | 'failed';
  created_at: Date;
  attempts: number;
}

class JobQueue {
  private jobs: Map<string, QueuedJob> = new Map();
  private processingQueue: QueuedJob[] = [];

  async add(type: string, data: any): Promise<string> {
    const id = `job-${type}-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
    const job: QueuedJob = {
      id,
      type,
      data,
      status: 'pending',
      created_at: new Date(),
      attempts: 0,
    };

    this.jobs.set(id, job);
    this.processingQueue.push(job);
    logger.info(`Job queued: ${id} (type: ${type})`);

    return id;
  }

  async getJob(id: string): Promise<QueuedJob | null> {
    return this.jobs.get(id) || null;
  }

  async updateStatus(id: string, status: QueuedJob['status']): Promise<void> {
    const job = this.jobs.get(id);
    if (job) {
      job.status = status;
      logger.info(`Job ${id} status updated to ${status}`);
    }
  }

  async getPendingJobs(limit = 10): Promise<QueuedJob[]> {
    return this.processingQueue
      .filter((j) => j.status === 'pending')
      .slice(0, limit);
  }

  getStats() {
    const statuses = Array.from(this.jobs.values()).reduce(
      (acc, job) => {
        acc[job.status] = (acc[job.status] || 0) + 1;
        return acc;
      },
      {} as Record<string, number>
    );

    return {
      total_jobs: this.jobs.size,
      by_status: statuses,
    };
  }
}

export const jobQueue = new JobQueue();

logger.info('Job queue initialized (in-memory). For production, integrate BullMQ with Redis.');
