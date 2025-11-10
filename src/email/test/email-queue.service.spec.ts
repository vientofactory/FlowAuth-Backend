import { Test, TestingModule } from '@nestjs/testing';
import { getQueueToken } from '@nestjs/bull';
import { EmailQueueService } from '../email-queue.service';
import {
  EmailJobType,
  EMAIL_PRIORITY,
} from '../interfaces/email-job.interface';

describe('EmailQueueService', () => {
  let service: EmailQueueService;
  let mockQueue: any;

  beforeEach(async () => {
    mockQueue = {
      add: jest.fn().mockResolvedValue({ id: '123' }),
      getActive: jest.fn().mockResolvedValue([]),
      getWaiting: jest.fn().mockResolvedValue([]),
      getCompleted: jest.fn().mockResolvedValue([]),
      getFailed: jest.fn().mockResolvedValue([]),
      getDelayed: jest.fn().mockResolvedValue([]),
      isPaused: jest.fn().mockResolvedValue(false),
      getJob: jest.fn(),
      pause: jest.fn(),
      resume: jest.fn(),
      clean: jest.fn().mockResolvedValue([]), // 빈 배열 반환하도록 모킹
      empty: jest.fn(),
    };

    const module: TestingModule = await Test.createTestingModule({
      providers: [
        EmailQueueService,
        {
          provide: getQueueToken('email'),
          useValue: mockQueue,
        },
      ],
    }).compile();

    service = module.get<EmailQueueService>(EmailQueueService);
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  describe('addWelcomeEmailJob', () => {
    it('should add welcome email job to queue', async () => {
      const to = 'test@example.com';
      const username = 'testuser';

      await service.addWelcomeEmailJob(to, username);

      expect(mockQueue.add).toHaveBeenCalledWith(
        EmailJobType.WELCOME,
        {
          type: EmailJobType.WELCOME,
          to,
          username,
        },
        expect.objectContaining({
          priority: EMAIL_PRIORITY.NORMAL,
        }),
      );
    });

    it('should add welcome email job with custom options', async () => {
      const to = 'test@example.com';
      const username = 'testuser';
      const options = { priority: EMAIL_PRIORITY.HIGH };

      await service.addWelcomeEmailJob(to, username, options);

      expect(mockQueue.add).toHaveBeenCalledWith(
        EmailJobType.WELCOME,
        {
          type: EmailJobType.WELCOME,
          to,
          username,
          priority: EMAIL_PRIORITY.HIGH,
        },
        expect.objectContaining({
          priority: EMAIL_PRIORITY.HIGH,
        }),
      );
    });
  });

  describe('addEmailVerificationJob', () => {
    it('should add email verification job with high priority', async () => {
      const to = 'test@example.com';
      const username = 'testuser';
      const verificationToken = 'token123';

      await service.addEmailVerificationJob(to, username, verificationToken);

      expect(mockQueue.add).toHaveBeenCalledWith(
        EmailJobType.EMAIL_VERIFICATION,
        {
          type: EmailJobType.EMAIL_VERIFICATION,
          to,
          username,
          verificationToken,
        },
        expect.objectContaining({
          priority: EMAIL_PRIORITY.HIGH,
        }),
      );
    });
  });

  describe('addSecurityAlertJob', () => {
    it('should add security alert job with critical priority', async () => {
      const to = 'test@example.com';
      const username = 'testuser';
      const alertType = 'login_attempt';
      const details = { ip: '192.168.1.1', userAgent: 'Chrome' };

      await service.addSecurityAlertJob(to, username, alertType, details);

      expect(mockQueue.add).toHaveBeenCalledWith(
        EmailJobType.SECURITY_ALERT,
        {
          type: EmailJobType.SECURITY_ALERT,
          to,
          username,
          alertType,
          details,
        },
        expect.objectContaining({
          priority: EMAIL_PRIORITY.CRITICAL,
        }),
      );
    });
  });

  describe('getQueueStats', () => {
    it('should return queue statistics', async () => {
      mockQueue.getActive.mockResolvedValue([1, 2]);
      mockQueue.getWaiting.mockResolvedValue([1, 2, 3]);
      mockQueue.getCompleted.mockResolvedValue([1]);
      mockQueue.getFailed.mockResolvedValue([]);
      mockQueue.getDelayed.mockResolvedValue([1]);
      mockQueue.isPaused.mockResolvedValue(true);

      const stats = await service.getQueueStats();

      expect(stats).toEqual({
        active: 2,
        waiting: 3,
        completed: 1,
        failed: 0,
        delayed: 1,
        paused: 1,
      });
    });
  });

  describe('retryFailedJobs', () => {
    it('should retry failed jobs', async () => {
      const mockJob = {
        id: '123',
        retry: jest.fn().mockResolvedValue(undefined),
      };
      mockQueue.getFailed.mockResolvedValue([mockJob]);

      const result = await service.retryFailedJobs(1);

      expect(mockJob.retry).toHaveBeenCalled();
      expect(result).toBe(1);
    });

    it('should handle retry failures gracefully', async () => {
      const mockJob = {
        id: '123',
        retry: jest.fn().mockRejectedValue(new Error('Retry failed')),
      };
      mockQueue.getFailed.mockResolvedValue([mockJob]);

      const result = await service.retryFailedJobs(1);

      expect(mockJob.retry).toHaveBeenCalled();
      expect(result).toBe(0); // No jobs successfully retried
    });
  });

  describe('pauseQueue and resumeQueue', () => {
    it('should pause the queue', async () => {
      await service.pauseQueue();
      expect(mockQueue.pause).toHaveBeenCalled();
    });

    it('should resume the queue', async () => {
      await service.resumeQueue();
      expect(mockQueue.resume).toHaveBeenCalled();
    });
  });

  describe('cleanQueue', () => {
    it('should clean the queue with default parameters', async () => {
      await service.cleanQueue();

      expect(mockQueue.clean).toHaveBeenCalledTimes(2);
      expect(mockQueue.clean).toHaveBeenCalledWith(86400000, 'completed', 1000);
      expect(mockQueue.clean).toHaveBeenCalledWith(86400000, 'failed', 1000);
    });

    it('should clean the queue with custom parameters', async () => {
      await service.cleanQueue(0, 500);

      expect(mockQueue.clean).toHaveBeenCalledTimes(2);
      expect(mockQueue.clean).toHaveBeenCalledWith(0, 'completed', 500);
      expect(mockQueue.clean).toHaveBeenCalledWith(0, 'failed', 500);
    });
  });

  describe('removeJob', () => {
    it('should remove job successfully', async () => {
      const mockJob = {
        remove: jest.fn().mockResolvedValue(undefined),
      };
      mockQueue.getJob.mockResolvedValue(mockJob);

      const result = await service.removeJob('123');

      expect(mockQueue.getJob).toHaveBeenCalledWith('123');
      expect(mockJob.remove).toHaveBeenCalled();
      expect(result).toBe(true);
    });

    it('should return false if job not found', async () => {
      mockQueue.getJob.mockResolvedValue(null);

      const result = await service.removeJob('123');

      expect(result).toBe(false);
    });
  });
});
