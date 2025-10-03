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
  `backupCodes` json DEFAULT NULL,
  `isActive` tinyint NOT NULL DEFAULT 1,
  `avatar` varchar(500) DEFAULT NULL,
  `bio` text,
  `website` varchar(255) DEFAULT NULL,
  `location` varchar(255) DEFAULT NULL,
  `createdAt` datetime(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  `updatedAt` datetime(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
  PRIMARY KEY (`id`),
  UNIQUE KEY `IDX_78a916df40e02a9deb1c4b75ed` (`username`),
  UNIQUE KEY `IDX_e12875dfb3b1d92d7d7c5377e2` (`email`)
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
  `tokenType` varchar(20) NOT NULL DEFAULT 'bearer',
  `isRevoked` tinyint NOT NULL DEFAULT 0,
  `revokedAt` datetime DEFAULT NULL,
  `isRefreshTokenUsed` tinyint NOT NULL DEFAULT 0,
  `userId` int DEFAULT NULL,
  `clientId` int NOT NULL,
  `createdAt` datetime(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  PRIMARY KEY (`id`),
  UNIQUE KEY `IDX_1e4a750a92c4a87a9e89c8d9e9` (`accessToken`),
  UNIQUE KEY `IDX_1e4a750a92c4a87a9e89c8d9e8` (`refreshToken`),
  KEY `IDX_1e4a750a92c4a87a9e89c8d9e7` (`clientId`,`userId`),
  KEY `FK_1e4a750a92c4a87a9e89c8d9e6` (`userId`),
  KEY `FK_1e4a750a92c4a87a9e89c8d9e5` (`clientId`),
  CONSTRAINT `FK_1e4a750a92c4a87a9e89c8d9e5` FOREIGN KEY (`clientId`) REFERENCES `client` (`id`),
  CONSTRAINT `FK_1e4a750a92c4a87a9e89c8d9e6` FOREIGN KEY (`userId`) REFERENCES `user` (`id`) ON DELETE SET NULL
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
  `isUsed` tinyint NOT NULL DEFAULT 0,
  `userId` int NOT NULL,
  `clientId` int NOT NULL,
  `createdAt` datetime(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  PRIMARY KEY (`id`),
  UNIQUE KEY `IDX_1e4a750a92c4a87a9e89c8d9e4` (`code`),
  KEY `IDX_1e4a750a92c4a87a9e89c8d9e3` (`clientId`,`userId`),
  KEY `FK_1e4a750a92c4a87a9e89c8d9e2` (`userId`),
  KEY `FK_1e4a750a92c4a87a9e89c8d9e1` (`clientId`),
  CONSTRAINT `FK_1e4a750a92c4a87a9e89c8d9e1` FOREIGN KEY (`clientId`) REFERENCES `client` (`id`),
  CONSTRAINT `FK_1e4a750a92c4a87a9e89c8d9e2` FOREIGN KEY (`userId`) REFERENCES `user` (`id`)
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
  UNIQUE KEY `IDX_1e4a750a92c4a87a9e89c8d9e0` (`name`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
```

> **참고**: 위 SQL 쿼리문들은 TypeORM 마이그레이션에서 자동으로 생성되는 것과 동일합니다. 수동으로 테이블을 생성할 때만 사용하세요.

### 4. 개발 서버 실행

```bash
npm run start:dev
```

서버가 `http://localhost:3000`에서 실행됩니다.

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
- isActive: boolean
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
- isUsed: boolean
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
- user: User (Foreign Key, Nullable)
- client: Client (Foreign Key)
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

## 📜 사용 가능한 스크립트

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

```env
# OAuth2 Configuration
OAUTH2_ACCESS_TOKEN_EXPIRY_HOURS=1
OAUTH2_REFRESH_TOKEN_EXPIRY_DAYS=30
OAUTH2_CODE_EXPIRY_MINUTES=10
OAUTH2_CODE_LENGTH=32

# OIDC Configuration (RSA 키 쌍)
# RSA 키 생성 방법:
# 1. 수동 생성:
#    openssl genrsa -out private.pem 2048
#    openssl rsa -in private.pem -pubout -out public.pem
# 2. 자동 생성 (권장):
#    ./generate_rsa_keys.sh
# 생성된 키를 환경변수에 설정
RSA_PRIVATE_KEY="-----BEGIN PRIVATE KEY-----\nYour RSA Private Key Here\n-----END PRIVATE KEY-----"
RSA_PUBLIC_KEY="-----BEGIN PUBLIC KEY-----\nYour RSA Public Key Here\n-----END PUBLIC KEY-----"

# Cache Configuration
CACHE_TTL=300000

# Cleanup Configuration
CLEANUP_CRON_EXPRESSION=0 0 * * *

# Frontend Configuration (for CORS)
FRONTEND_URL=http://localhost:5173
```

## 보안 기능

- **JWT 토큰 기반 인증**
- **RSA 서명**: ID 토큰의 보안 서명 (RS256 알고리즘)
- **OpenID Connect 지원**: ID 토큰 및 UserInfo 엔드포인트
- **비밀번호 해싱 (bcrypt)**
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

생성된 키쌍을 `.env` 파일에 복사하여 사용하세요.

## 라이선스

This project is licensed under the MIT License.
