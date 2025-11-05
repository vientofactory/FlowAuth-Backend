/**
 * 이메일 작업 타입 정의
 */
export enum EmailJobType {
  WELCOME = 'welcome',
  EMAIL_VERIFICATION = 'email-verification',
  PASSWORD_RESET = 'password-reset',
  SECURITY_ALERT = 'security-alert',
  TWO_FA_ENABLED = '2fa-enabled',
  CLIENT_CREATED = 'client-created',
  TEMPLATE_EMAIL = 'template-email',
}

/**
 * 기본 이메일 작업 페이로드
 */
export interface BaseEmailJobPayload {
  to: string;
  priority?: number;
  delay?: number;
  attempts?: number;
}

/**
 * 환영 이메일 페이로드
 */
export interface WelcomeEmailJobPayload extends BaseEmailJobPayload {
  type: EmailJobType.WELCOME;
  username: string;
}

/**
 * 이메일 인증 페이로드
 */
export interface EmailVerificationJobPayload extends BaseEmailJobPayload {
  type: EmailJobType.EMAIL_VERIFICATION;
  username: string;
  verificationToken: string;
}

/**
 * 비밀번호 재설정 페이로드
 */
export interface PasswordResetJobPayload extends BaseEmailJobPayload {
  type: EmailJobType.PASSWORD_RESET;
  username: string;
  resetToken: string;
}

/**
 * 보안 알림 페이로드
 */
export interface SecurityAlertJobPayload extends BaseEmailJobPayload {
  type: EmailJobType.SECURITY_ALERT;
  username: string;
  alertType: string;
  details: { [key: string]: unknown };
}

/**
 * 2FA 활성화 페이로드
 */
export interface TwoFAEnabledJobPayload extends BaseEmailJobPayload {
  type: EmailJobType.TWO_FA_ENABLED;
  username: string;
}

/**
 * OAuth2 클라이언트 생성 페이로드
 */
export interface ClientCreatedJobPayload extends BaseEmailJobPayload {
  type: EmailJobType.CLIENT_CREATED;
  username: string;
  clientName: string;
  clientId: string;
}

/**
 * 템플릿 이메일 페이로드 (범용)
 */
export interface TemplateEmailJobPayload extends BaseEmailJobPayload {
  type: EmailJobType.TEMPLATE_EMAIL;
  subject: string;
  templateName: string;
  context: { [key: string]: unknown };
}

/**
 * 모든 이메일 작업 페이로드의 유니온 타입
 */
export type EmailJobPayload =
  | WelcomeEmailJobPayload
  | EmailVerificationJobPayload
  | PasswordResetJobPayload
  | SecurityAlertJobPayload
  | TwoFAEnabledJobPayload
  | ClientCreatedJobPayload
  | TemplateEmailJobPayload;

/**
 * 작업 우선순위 상수
 */
export const EMAIL_PRIORITY = {
  LOW: 1,
  NORMAL: 5,
  HIGH: 10,
  CRITICAL: 15,
} as const;

/**
 * 작업 설정 옵션
 */
export interface EmailJobOptions {
  priority?: number;
  delay?: number; // 지연 시간 (밀리초)
  attempts?: number; // 최대 재시도 횟수
  removeOnComplete?: number; // 완료된 작업 보관 개수
  removeOnFail?: number; // 실패한 작업 보관 개수
  backoff?: {
    type: 'fixed' | 'exponential';
    delay: number;
  };
}

/**
 * 기본 작업 설정
 */
export const DEFAULT_EMAIL_JOB_OPTIONS: EmailJobOptions = {
  attempts: 3,
  removeOnComplete: 100,
  removeOnFail: 50,
  backoff: {
    type: 'exponential',
    delay: 2000,
  },
};

/**
 * 작업 타입별 기본 설정
 */
export const EMAIL_JOB_CONFIGS: Record<EmailJobType, EmailJobOptions> = {
  [EmailJobType.WELCOME]: {
    ...DEFAULT_EMAIL_JOB_OPTIONS,
    priority: EMAIL_PRIORITY.NORMAL,
  },
  [EmailJobType.EMAIL_VERIFICATION]: {
    ...DEFAULT_EMAIL_JOB_OPTIONS,
    priority: EMAIL_PRIORITY.HIGH,
    attempts: 5, // 중요한 이메일이므로 더 많이 재시도
  },
  [EmailJobType.PASSWORD_RESET]: {
    ...DEFAULT_EMAIL_JOB_OPTIONS,
    priority: EMAIL_PRIORITY.HIGH,
    attempts: 5,
  },
  [EmailJobType.SECURITY_ALERT]: {
    ...DEFAULT_EMAIL_JOB_OPTIONS,
    priority: EMAIL_PRIORITY.CRITICAL,
    attempts: 5,
  },
  [EmailJobType.TWO_FA_ENABLED]: {
    ...DEFAULT_EMAIL_JOB_OPTIONS,
    priority: EMAIL_PRIORITY.HIGH,
  },
  [EmailJobType.CLIENT_CREATED]: {
    ...DEFAULT_EMAIL_JOB_OPTIONS,
    priority: EMAIL_PRIORITY.NORMAL,
  },
  [EmailJobType.TEMPLATE_EMAIL]: {
    ...DEFAULT_EMAIL_JOB_OPTIONS,
    priority: EMAIL_PRIORITY.NORMAL,
  },
};
