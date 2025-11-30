# FlowAuth Backend

FlowAuth의 백엔드 API 서버입니다. NestJS와 TypeORM을 기반으로 OAuth2 및 OpenID Connect 인증 시스템을 구현합니다.

## 기술 스택

- **Framework**: [NestJS](https://nestjs.com/)
- **Database**: MariaDB + [TypeORM](https://typeorm.io/)
- **Authentication**: Passport.js + JWT + OpenID Connect
- **OAuth2/OIDC**: Authorization Code Grant + PKCE + OpenID Connect Core 1.0
- **Validation**: class-validator + class-transformer
- **Security**: Helmet, CORS, Rate Limiting
- **Testing**: Jest + Supertest
- **Language**: TypeScript
- **Documentation**: Swagger/OpenAPI

## 사전 요구사항

- Node.js (v18 이상)
- MariaDB (또는 MySQL 호환 데이터베이스)
- npm 또는 yarn

## 빠른 시작

### 1. 의존성 설치

```bash
npm install
```

### 2. 환경 변수 설정

```bash
cp .env.example .env
```

주요 환경 변수:

```env
# Database Configuration
DB_HOST=localhost
DB_PORT=3306
DB_USERNAME=root
DB_PASSWORD=your_password_here
DB_NAME=flowauth

# JWT Configuration
JWT_SECRET=your_super_secret_jwt_key_here
JWT_EXPIRES_IN=1h

# Application Configuration
PORT=3000
NODE_ENV=development
```

### 3. 데이터베이스 설정

```bash
# 데이터베이스 생성 (MariaDB)
mysql -u root -p -e "CREATE DATABASE flowauth;"

# 마이그레이션 실행
npm run migration:run

# 초기 데이터 시딩 (OAuth2 기본 데이터)
npm run seed
```

### 수동 테이블 생성 (선택사항)

TypeORM 마이그레이션을 사용하지 않고 수동으로 테이블을 생성하려면 다음 SQL 쿼리문을 사용하세요:

#### 1. 사용자 테이블 (User)

```sql
CREATE TABLE `user` (
  `id` int NOT NULL AUTO_INCREMENT,
  `username` varchar(100) NOT NULL,
  `email` varchar(255) NOT NULL,
  `password` varchar(255) NOT NULL,
  `firstName` varchar(100) DEFAULT NULL,
  `lastName` varchar(100) DEFAULT NULL,
  `userType` varchar(20) NOT NULL DEFAULT 'regular',
  `isEmailVerified` tinyint NOT NULL DEFAULT 0,
  `permissions` bigint NOT NULL DEFAULT 1,
  `lastLoginAt` datetime DEFAULT NULL,
  `twoFactorSecret` varchar(255) DEFAULT NULL,
  `isTwoFactorEnabled` tinyint NOT NULL DEFAULT 0,
  `backupCodes` text DEFAULT NULL,
  `isActive` tinyint NOT NULL DEFAULT 1,
  `avatar` text DEFAULT NULL,
  `bio` text DEFAULT NULL,
  `website` text DEFAULT NULL,
  `location` text DEFAULT NULL,
  `createdAt` datetime(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  `updatedAt` datetime(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
  PRIMARY KEY (`id`),
  UNIQUE KEY `IDX_78a916df40e02a9deb1c4b75ed` (`username`),
  UNIQUE KEY `IDX_e12875dfb3b1d92d7d7c5377e2` (`email`),
  KEY `IDX_user_id_isActive` (`id`,`isActive`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
```

#### 2. 클라이언트 테이블 (Client)

```sql
CREATE TABLE `client` (
  `id` int NOT NULL AUTO_INCREMENT,
  `clientId` varchar(255) NOT NULL,
  `clientSecret` varchar(255) DEFAULT NULL,
  `redirectUris` json NOT NULL,
  `grants` json NOT NULL,
  `scopes` json DEFAULT NULL,
  `name` varchar(255) NOT NULL,
  `description` varchar(500) DEFAULT NULL,
  `isActive` tinyint NOT NULL DEFAULT 1,
  `isConfidential` tinyint NOT NULL DEFAULT 0,
  `logoUri` varchar(500) DEFAULT NULL,
  `termsOfServiceUri` varchar(500) DEFAULT NULL,
  `policyUri` varchar(500) DEFAULT NULL,
  `userId` int NOT NULL,
  `createdAt` datetime(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  `updatedAt` datetime(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
  PRIMARY KEY (`id`),
  UNIQUE KEY `IDX_368e4240b4c7f4a6e6e1b7c6b8` (`clientId`),
  KEY `FK_368e4240b4c7f4a6e6e1b7c6b8a` (`userId`),
  CONSTRAINT `FK_368e4240b4c7f4a6e6e1b7c6b8a` FOREIGN KEY (`userId`) REFERENCES `user` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
```

#### 3. 토큰 테이블 (Token)

```sql
CREATE TABLE `token` (
  `id` int NOT NULL AUTO_INCREMENT,
  `accessToken` varchar(2048) NOT NULL,
  `refreshToken` varchar(2048) DEFAULT NULL,
  `expiresAt` datetime NOT NULL,
  `refreshExpiresAt` datetime DEFAULT NULL,
  `scopes` json DEFAULT NULL,
  `tokenType` varchar(20) NOT NULL DEFAULT 'login',
  `isRevoked` tinyint NOT NULL DEFAULT 0,
  `revokedAt` datetime DEFAULT NULL,
  `isRefreshTokenUsed` tinyint NOT NULL DEFAULT 0,
  `revokedReason` varchar(255) DEFAULT NULL,
  `tokenFamily` varchar(255) DEFAULT NULL,
  `rotationGeneration` int NOT NULL DEFAULT 1,
  `lastUsedAt` datetime DEFAULT NULL,
  `lastUsedIp` varchar(45) DEFAULT NULL,
  `userId` int DEFAULT NULL,
  `clientId` int DEFAULT NULL,
  `createdAt` datetime(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  `updatedAt` datetime(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
  PRIMARY KEY (`id`),
  UNIQUE KEY `IDX_token_accessToken` (`accessToken`),
  UNIQUE KEY `IDX_token_refreshToken` (`refreshToken`),
  UNIQUE KEY `IDX_token_family_generation` (`tokenFamily`,`rotationGeneration`),
  KEY `IDX_token_user_client` (`userId`,`clientId`),
  KEY `IDX_token_revoked_expires` (`isRevoked`,`expiresAt`),
  KEY `IDX_token_lastUsedAt` (`lastUsedAt`),
  KEY `IDX_token_refresh_expires_used` (`refreshExpiresAt`,`isRefreshTokenUsed`),
  KEY `FK_token_userId` (`userId`),
  KEY `FK_token_clientId` (`clientId`),
  CONSTRAINT `FK_token_clientId` FOREIGN KEY (`clientId`) REFERENCES `client` (`id`),
  CONSTRAINT `FK_token_userId` FOREIGN KEY (`userId`) REFERENCES `user` (`id`) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
```

#### 4. 인가 코드 테이블 (AuthorizationCode)

```sql
CREATE TABLE `authorization_code` (
  `id` int NOT NULL AUTO_INCREMENT,
  `code` varchar(128) NOT NULL,
  `expiresAt` datetime NOT NULL,
  `redirectUri` varchar(500) DEFAULT NULL,
  `scopes` json DEFAULT NULL,
  `state` varchar(256) DEFAULT NULL,
  `codeChallenge` varchar(128) DEFAULT NULL,
  `codeChallengeMethod` varchar(10) DEFAULT NULL,
  `nonce` varchar(128) DEFAULT NULL,
  `authTime` bigint DEFAULT NULL,
  `isUsed` tinyint NOT NULL DEFAULT 0,
  `userId` int NOT NULL,
  `clientId` int NOT NULL,
  `createdAt` datetime(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  PRIMARY KEY (`id`),
  UNIQUE KEY `IDX_authcode_code` (`code`),
  KEY `IDX_authcode_client_user` (`clientId`,`userId`),
  KEY `FK_authcode_userId` (`userId`),
  KEY `FK_authcode_clientId` (`clientId`),
  CONSTRAINT `FK_authcode_clientId` FOREIGN KEY (`clientId`) REFERENCES `client` (`id`),
  CONSTRAINT `FK_authcode_userId` FOREIGN KEY (`userId`) REFERENCES `user` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
```

#### 5. 스코프 테이블 (Scope)

```sql
CREATE TABLE `scope` (
  `id` int NOT NULL AUTO_INCREMENT,
  `name` varchar(255) NOT NULL,
  `description` varchar(255) NOT NULL,
  `isDefault` tinyint NOT NULL DEFAULT 1,
  `isActive` tinyint NOT NULL DEFAULT 1,
  `createdAt` datetime(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  `updatedAt` datetime(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
  PRIMARY KEY (`id`),
  UNIQUE KEY `IDX_scope_name` (`name`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
```

#### 6. 감사 로그 테이블 (AuditLog)

```sql
CREATE TABLE `audit_log` (
  `id` int NOT NULL AUTO_INCREMENT,
  `eventType` varchar(50) NOT NULL,
  `severity` varchar(20) NOT NULL DEFAULT 'low',
  `description` text NOT NULL,
  `metadata` json DEFAULT NULL,
  `ipAddress` varchar(45) DEFAULT NULL,
  `userAgent` varchar(500) DEFAULT NULL,
  `httpMethod` varchar(10) DEFAULT NULL,
  `endpoint` varchar(500) DEFAULT NULL,
  `responseStatus` int DEFAULT NULL,
  `userId` int DEFAULT NULL,
  `clientId` int DEFAULT NULL,
  `resourceId` int DEFAULT NULL,
  `resourceType` varchar(100) DEFAULT NULL,
  `createdAt` datetime(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  PRIMARY KEY (`id`),
  KEY `IDX_audit_log_user_created` (`userId`, `createdAt`),
  KEY `IDX_audit_log_client_created` (`clientId`, `createdAt`),
  KEY `IDX_audit_log_event_created` (`eventType`, `createdAt`),
  KEY `IDX_audit_log_severity_created` (`severity`, `createdAt`),
  KEY `IDX_audit_log_ip` (`ipAddress`),
  KEY `FK_audit_log_user` (`userId`),
  KEY `FK_audit_log_client` (`clientId`),
  CONSTRAINT `FK_audit_log_user` FOREIGN KEY (`userId`) REFERENCES `user` (`id`) ON DELETE SET NULL,
  CONSTRAINT `FK_audit_log_client` FOREIGN KEY (`clientId`) REFERENCES `client` (`id`) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
```

#### 7. 이메일 인증 토큰 테이블 (EmailVerificationToken)

```sql
CREATE TABLE `email_verification_tokens` (
  `id` int NOT NULL AUTO_INCREMENT,
  `token` varchar(255) NOT NULL,
  `email` varchar(255) NOT NULL,
  `user_id` int NOT NULL,
  `used` tinyint NOT NULL DEFAULT 0,
  `expires_at` datetime NOT NULL,
  `created_at` datetime(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  PRIMARY KEY (`id`),
  UNIQUE KEY `IDX_email_verification_token` (`token`),
  KEY `IDX_email_verification_email_used_expires` (`email`, `used`, `expires_at`),
  KEY `FK_email_verification_user` (`user_id`),
  CONSTRAINT `FK_email_verification_user` FOREIGN KEY (`user_id`) REFERENCES `user` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
```

#### 8. 비밀번호 재설정 토큰 테이블 (PasswordResetToken)

```sql
CREATE TABLE `password_reset_tokens` (
  `id` int NOT NULL AUTO_INCREMENT,
  `token` varchar(255) NOT NULL,
  `email` varchar(255) NOT NULL,
  `user_id` int NOT NULL,
  `used` tinyint NOT NULL DEFAULT 0,
  `expires_at` datetime NOT NULL,
  `created_at` datetime(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  PRIMARY KEY (`id`),
  UNIQUE KEY `IDX_password_reset_token` (`token`),
  KEY `IDX_password_reset_email_used_expires` (`email`, `used`, `expires_at`),
  KEY `FK_password_reset_user` (`user_id`),
  CONSTRAINT `FK_password_reset_user` FOREIGN KEY (`user_id`) REFERENCES `user` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
```

### 4. 개발 서버 실행

```bash
npm run start:dev
```

서버가 `http://localhost:3000`에서 실행됩니다.

## 프로젝트 구조

```
backend/
├── Dockerfile                    # Docker 이미지 설정
├── eslint.config.mjs            # ESLint 설정
├── nest-cli.json               # NestJS CLI 설정
├── package.json                # 프로젝트 의존성 및 스크립트
├── renovate.json               # Renovate 설정
├── tsconfig.build.json         # TypeScript 빌드 설정
├── tsconfig.json               # TypeScript 설정
├── coverage/                   # 테스트 커버리지 보고서
├── keys/                       # RSA 키 파일
├── logs/                       # 애플리케이션 로그
├── migrations/                 # 데이터베이스 마이그레이션 파일
├── src/                        # 소스 코드
│   ├── main.ts                 # 애플리케이션 진입점
│   ├── api/                    # API 관련 모듈
│   ├── auth/                   # 인증 모듈
│   ├── cache/                  # 캐시 모듈
│   ├── common/                 # 공통 유틸리티
│   ├── config/                 # 설정 모듈
│   ├── constants/              # 상수 정의
│   ├── dashboard/              # 대시보드 모듈
│   ├── database/               # 데이터베이스 모듈
│   ├── email/                  # 이메일 모듈
│   ├── health/                 # 헬스체크 모듈
│   ├── migrations/             # 마이그레이션 모듈
│   ├── oauth2/                 # OAuth2 모듈
│   ├── profile/                # 프로필 모듈
│   ├── scripts/                # 스크립트 모듈
│   ├── types/                  # 타입 정의
│   ├── upload/                 # 파일 업로드 모듈
│   └── utils/                  # 유틸리티 함수
├── test/                       # 테스트 파일
├── uploads/                    # 업로드된 파일
└── README.md
```

## API 문서

### Swagger UI

API 문서를 확인하려면 브라우저에서 `http://localhost:3000/api`로 접속하세요.

### 주요 엔드포인트

#### 인증 관련

- `POST /auth/login` - 사용자 로그인
- `POST /auth/register` - 사용자 등록
- `GET /auth/profile` - 프로필 조회

#### OAuth2 관련

- `GET /oauth2/authorize` - 인가 요청
- `POST /oauth2/token` - 토큰 발급
- `GET /oauth2/userinfo` - 사용자 정보 조회
- `POST /oauth2/authorize/consent` - 동의 처리

#### 클라이언트 관리

- `GET /clients` - 클라이언트 목록 조회
- `POST /clients` - 새 클라이언트 생성
- `PUT /clients/:id` - 클라이언트 수정
- `DELETE /clients/:id` - 클라이언트 삭제

#### 헬스체크

- `GET /health` - 애플리케이션 헬스체크 (데이터베이스, 메모리, RSA 키 검증)

## 데이터베이스 스키마

### 주요 엔티티

#### User (사용자)

```sql
- id: number (Primary Key)
- email: string (Unique)
- username: string (Unique)
- password: string (Hashed)
- roles: string[] (JSON Array)
- createdAt: Date
- updatedAt: Date
```

#### Client (OAuth2 클라이언트)

```sql
- id: number (Primary Key)
- clientId: string (Unique)
- clientSecret: string (Hashed)
- name: string
- description: string
- redirectUris: string[] (JSON Array)
- isActive: tinyint (0/1)
- createdAt: Date
- updatedAt: Date
```

#### AuthorizationCode (인가 코드)

```sql
- id: number (Primary Key)
- code: string (Unique)
- expiresAt: Date
- redirectUri: string
- scopes: string[] (JSON Array)
- state: string
- codeChallenge: string
- codeChallengeMethod: string
- isUsed: tinyint (0/1)
- user: User (Foreign Key)
- client: Client (Foreign Key)
```

#### Token (액세스 토큰)

```sql
- id: number (Primary Key)
- accessToken: string (Unique)
- refreshToken: string (Unique)
- expiresAt: Date
- refreshExpiresAt: Date
- scopes: string[] (JSON Array)
- tokenType: string (기본값: 'login')
- isRevoked: tinyint (기본값: 0)
- revokedAt: Date (Nullable)
- isRefreshTokenUsed: tinyint (기본값: 0)
- revokedReason: string (Nullable)
- tokenFamily: string (Nullable)
- rotationGeneration: number (기본값: 1)
- lastUsedAt: Date (Nullable)
- lastUsedIp: string (Nullable)
- user: User (Foreign Key, Nullable)
- client: Client (Foreign Key, Nullable)
- createdAt: Date
- updatedAt: Date
```

## 테스트

```bash
# 단위 테스트 실행
npm run test

# 테스트 커버리지 확인
npm run test:cov

# E2E 테스트 실행
npm run test:e2e
```

## 사용 가능한 스크립트

```bash
# 개발 서버
npm run start:dev

# 프로덕션 빌드
npm run build
npm run start:prod

# 코드 품질
npm run format    # 코드 포맷팅
npm run lint      # 린팅

# 데이터베이스
npm run migration:run     # 마이그레이션 실행
npm run migration:revert  # 마이그레이션 되돌리기
npm run seed             # 초기 데이터 시딩

# TypeORM CLI
npm run typeorm
```

## 환경 설정

### 추가 환경 변수 (선택사항)

OIDC 관련 변수는 누락될 경우 OpenID Connect 관련 기능이 제대로 작동하지 않을 수 있습니다.

```env
# Snowflake ID Generator Configuration
NODE_ID=1  # Snowflake ID 생성에 사용되는 노드 ID (0-1023 범위, 기본값: 1)

# OAuth2 Configuration
OAUTH2_ACCESS_TOKEN_EXPIRY_HOURS=1
OAUTH2_REFRESH_TOKEN_EXPIRY_DAYS=30
OAUTH2_CODE_EXPIRY_MINUTES=10
OAUTH2_CODE_LENGTH=32

# OIDC Configuration (RSA 키)
# RSA 키는 환경변수 또는 파일로부터 로드할 수 있습니다.

# 방법 1: 환경변수에 직접 설정 (기존 방식)
RSA_PRIVATE_KEY="-----BEGIN PRIVATE KEY-----\nYour RSA Private Key Here\n-----END PRIVATE KEY-----"
RSA_PUBLIC_KEY="-----BEGIN PUBLIC KEY-----\nYour RSA Public Key Here\n-----END PUBLIC KEY-----"

# 방법 2: 파일 경로 지정 (권장)
RSA_PRIVATE_KEY_FILE="./keys/private.pem"
RSA_PUBLIC_KEY_FILE="./keys/public.pem"

# RSA 키 생성 방법:
# 1. 수동 생성:
#    openssl genrsa -out private.pem 2048
#    openssl rsa -in private.pem -pubout -out public.pem
# 2. 자동 생성 (권장):
#    ./generate_rsa_keys.sh --save-files
# 생성된 키를 환경변수에 설정하거나 파일로 저장하세요.

# Cache Configuration
CACHE_TTL=300000

# Cleanup Configuration
CLEANUP_CRON_EXPRESSION=0 0 * * *

# Email Configuration
# SMTP 설정 (이메일 인증, 비밀번호 재설정 등에 사용)
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_SECURE=0
SMTP_USER=your-email@gmail.com
SMTP_PASS=your-app-password

# 발신자 정보
SMTP_FROM_NAME=FlowAuth
SMTP_FROM_EMAIL=noreply@yourdomain.com

# 이메일 템플릿 설정 (선택사항)
# EMAIL_TEMPLATE_DIR=./src/email/templates

# Email Queue Configuration (Redis 기반 Bull Queue)
# Redis 연결 설정
REDIS_HOST=localhost
REDIS_PORT=6379
REDIS_PASSWORD=
REDIS_DB=0

# 큐 설정
QUEUE_NAME=email_queue
QUEUE_CONCURRENCY=10
QUEUE_MAX_ATTEMPTS=3
QUEUE_RETRY_DELAY=5000

# Frontend Configuration (for CORS)
# Development environment
FRONTEND_URL=http://localhost:5173

# Production environment (multiple domains supported)
# FRONTEND_URL=https://app.yourdomain.com,https://www.yourdomain.com
```

### CORS 설정

FlowAuth 백엔드는 `FRONTEND_URL` 환경변수를 통해 CORS(Cross-Origin Resource Sharing)를 설정합니다.

**개발 환경**:

```env
FRONTEND_URL=http://localhost:5173
```

**프로덕션 환경** (여러 도메인 지원):

```env
FRONTEND_URL=https://app.yourdomain.com,https://www.yourdomain.com,https://admin.yourdomain.com
```

**특징**:

- 개발 환경에서는 `localhost` 및 `127.0.0.1` 기반 URL들이 자동으로 허용됩니다
- 프로덕션 환경에서는 `FRONTEND_URL`에 명시된 도메인만 허용됩니다
- 여러 도메인은 쉼표(`,`)로 구분하여 설정할 수 있습니다
- 설정되지 않은 origin에서의 요청은 CORS 오류가 발생합니다

## 이메일 및 큐 설정

FlowAuth는 이메일 인증, 비밀번호 재설정, 알림 등을 위해 SMTP 기반의 이메일 시스템과 Redis 기반의 큐 시스템을 사용합니다.

### 이메일 설정 (SMTP)

#### 1. Gmail 사용 시 설정

```env
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_SECURE=0
SMTP_USER=your-email@gmail.com
SMTP_PASS=your-app-password  # Gmail 앱 비밀번호 필요
```

**Gmail 앱 비밀번호 생성 방법**:

1. Google 계정 > 보안 > 2단계 인증 활성화
2. Google 계정 > 보안 > 앱 비밀번호 생성
3. 생성된 16자리 비밀번호를 `SMTP_PASS`에 설정

#### 2. 기타 SMTP 서비스 설정 예시

**Outlook/Hotmail**:

**Outlook/Hotmail**:

```env
SMTP_HOST=smtp.live.com
SMTP_PORT=587
SMTP_SECURE=0
```

**Yahoo Mail**:

````env
**Yahoo Mail**:
```env
SMTP_HOST=smtp.mail.yahoo.com
SMTP_PORT=587
SMTP_SECURE=0
````

````

**사용자 정의 SMTP 서버**:

```env
SMTP_HOST=mail.yourdomain.com
SMTP_PORT=465
SMTP_SECURE=1  # SSL/TLS 사용
````

### Redis 및 큐 설정

FlowAuth는 이메일 전송을 위해 Redis 기반의 Bull Queue를 사용하여 비동기 처리를 수행합니다.

#### 1. Redis 설치

**macOS (Homebrew)**:

```bash
brew install redis
brew services start redis
```

**Ubuntu/Debian**:

```bash
sudo apt update
sudo apt install redis-server
sudo systemctl start redis-server
```

**Docker**:

```bash
docker run -d --name redis -p 6379:6379 redis:alpine
```

#### 2. Redis 연결 설정

```env
REDIS_HOST=localhost
REDIS_PORT=6379
REDIS_PASSWORD=          # 비밀번호가 설정된 경우
REDIS_DB=0              # 데이터베이스 번호 (0-15)
```

#### 3. 큐 성능 튜닝

```env
QUEUE_CONCURRENCY=10     # 동시 처리할 작업 수
QUEUE_MAX_ATTEMPTS=3     # 실패 시 재시도 횟수
QUEUE_RETRY_DELAY=5000   # 재시도 대기 시간 (밀리초)
```

### 이메일 템플릿

FlowAuth는 다음과 같은 이메일 템플릿을 제공합니다:

- **환영 이메일**: 회원가입 완료 시 발송
- **이메일 인증**: 회원가입 시 이메일 주소 인증
- **비밀번호 재설정**: 비밀번호 찾기 요청 시 발송
- **보안 알림**: 로그인, 비밀번호 변경 등 보안 관련 알림
- **2FA 활성화**: 2단계 인증 설정 완료 알림
- **클라이언트 생성**: OAuth2 클라이언트 생성 알림

### 이메일 기능 테스트

이메일 설정이 올바른지 테스트하려면:

1. **회원가입 테스트**: 새 계정으로 회원가입하여 인증 이메일 수신 확인
2. **비밀번호 재설정 테스트**: 비밀번호 찾기 기능으로 재설정 이메일 수신 확인
3. **Redis 연결 테스트**: 헬스체크 엔드포인트 (`GET /health`) 호출하여 Redis 상태 확인

### 문제 해결

#### 이메일이 발송되지 않는 경우

1. **SMTP 설정 확인**:

   ```bash
   # 환경변수가 올바르게 설정되었는지 확인
   echo $SMTP_HOST $SMTP_PORT $SMTP_USER
   ```

2. **방화벽 및 포트 확인**:

   ```bash
   # SMTP 포트 연결 테스트
   telnet smtp.gmail.com 587
   ```

3. **앱 로그 확인**:
   ```bash
   # 이메일 관련 오류 로그 확인
   npm run start:dev
   ```

#### Redis 연결 오류

1. **Redis 서비스 상태 확인**:

   ```bash
   # Redis 서버 실행 상태 확인
   redis-cli ping  # PONG 응답이 와야 함
   ```

2. **포트 및 연결 확인**:

   ```bash
   # Redis 포트 확인
   netstat -tlnp | grep 6379
   ```

3. **Redis 로그 확인**:
   ```bash
   # Redis 로그 확인 (설치 방법에 따라 경로가 다를 수 있음)
   tail -f /var/log/redis/redis-server.log
   ```

### 프로덕션 환경 권장사항

1. **이메일 서비스**: 프로덕션에서는 SendGrid, AWS SES, Mailgun 등 전문 이메일 서비스 사용 권장
2. **Redis 보안**: Redis에 비밀번호 설정 및 방화벽 구성
3. **모니터링**: 이메일 발송 실패율 및 큐 처리 성능 모니터링
4. **백업**: Redis 데이터 백업 설정 (큐 데이터 복구용)

## 보안 기능

- **JWT 토큰 기반 인증**
- **RSA 서명**: ID 토큰의 보안 서명 (RS256 알고리즘)
- **OpenID Connect 지원**: ID 토큰 및 UserInfo 엔드포인트
- **비밀번호 해싱 (bcrypt)**
- **이메일 인증 강제**: 이메일 미인증 시 로그인 차단
- **헬멧 (Helmet) 보안 헤더**
- **CORS 설정**
- **레이트 리미팅**
- **PKCE (Proof Key for Code Exchange) 지원**
- **인가 코드 만료 (기본 10분)**
- **토큰 만료 관리**
- **OIDC 스코프 지원**: openid, profile, email

## 문제 해결

### OAuth2 인증이 작동하지 않는 경우

**문제**: `error=server_error&error_description=Internal+server+error`

**해결 방법**:

1. 데이터베이스에 OAuth2 스코프가 있는지 확인:

   ```bash
   mysql -u root -p -e "USE flowauth; SELECT name FROM scope;"
   ```

2. 스코프가 없다면 시드 실행:

   ```bash
   npm run seed
   ```

3. 시드 실행 후 다시 OAuth2 인증 시도

### 데이터베이스 연결 오류

**문제**: `ER_ACCESS_DENIED_ERROR` 또는 연결 실패

**해결 방법**:

1. `.env` 파일의 데이터베이스 설정 확인
2. MariaDB 서비스가 실행 중인지 확인
3. 데이터베이스 권한 확인

### 마이그레이션 오류

**문제**: 마이그레이션 실행 실패

**해결 방법**:

1. 데이터베이스가 생성되어 있는지 확인
2. 이전 마이그레이션이 성공적으로 실행되었는지 확인
3. 마이그레이션 파일의 구문 오류 확인

### 이메일 인증 관련 오류

**문제**: 이메일 인증 링크가 작동하지 않음

**해결 방법**:

1. **SMTP 설정 확인**:

   ```bash
   # .env 파일의 SMTP 설정이 올바른지 확인
   cat .env | grep SMTP
   ```

2. **Redis 연결 확인**:

   ```bash
   # Redis 서비스 실행 상태 확인
   redis-cli ping
   ```

3. **이메일 큐 상태 확인**:
   - 헬스체크 엔드포인트 `/health` 호출
   - 이메일 큐 처리 상태 및 실패 작업 확인

4. **방화벽 설정**:
   - SMTP 포트 (587, 465, 25) 방화벽 허용 확인
   - 외부 SMTP 서버 연결 가능 여부 확인

**문제**: 이메일이 스팸함으로 들어감

**해결 방법**:

1. SPF, DKIM, DMARC 레코드 설정 (도메인 이메일 사용 시)
2. 전문 이메일 서비스 사용 (SendGrid, AWS SES 등)
3. 발신자 이메일 주소와 실제 도메인 일치 확인

## 기여하기

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## RSA 키 생성 스크립트

프로젝트에는 OIDC를 위한 RSA 키쌍을 자동으로 생성하는 편의 스크립트가 포함되어 있습니다.

### 사용법

```bash
# backend 디렉토리에서 실행
./generate_rsa_keys.sh
```

### 옵션

- `--save-files`: 키를 파일로 저장 (`./keys` 디렉토리에 저장)
- `--output-dir DIR`: 키 파일 저장 디렉토리 지정 (기본: `./keys`)
- `--env-only`: 환경변수 형식으로만 출력 (기본 동작)
- `--help`: 도움말 표시

### 예시

```bash
# 환경변수만 출력 (기본)
./generate_rsa_keys.sh

# 파일로 저장하고 환경변수도 출력
./generate_rsa_keys.sh --save-files

# 사용자 지정 디렉토리에 저장
./generate_rsa_keys.sh --save-files --output-dir ./config/keys
```

파일로 저장한 경우, 생성된 파일 경로를 환경변수에 설정하세요:

```env
RSA_PRIVATE_KEY_FILE="./keys/private.pem"
RSA_PUBLIC_KEY_FILE="./keys/public.pem"
```

## 라이선스

This project is licensed under the MIT License.
