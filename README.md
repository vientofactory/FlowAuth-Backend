# FlowAuth Backend

FlowAuth의 백엔드 API 서버입니다. NestJS와 TypeORM을 기반으로 OAuth2 인증 시스템을 구현합니다.

## 🚀 기술 스택

- **Framework**: [NestJS](https://nestjs.com/)
- **Database**: MySQL + [TypeORM](https://typeorm.io/)
- **Authentication**: Passport.js + JWT
- **Validation**: class-validator + class-transformer
- **Security**: Helmet, CORS, Rate Limiting
- **Testing**: Jest + Supertest
- **Language**: TypeScript
- **Documentation**: Swagger/OpenAPI

## 📋 사전 요구사항

- Node.js (v18 이상)
- MySQL (또는 호환되는 데이터베이스)
- npm 또는 yarn

## 🛠 설치 및 실행

### 1. 의존성 설치

```bash
npm install
```

### 2. 환경 변수 설정

`.env.example` 파일을 복사하여 `.env` 파일을 생성하고 필요한 값들을 설정하세요:

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
DB_CONNECTION_LIMIT=10
DB_ACQUIRE_TIMEOUT=60000
DB_TIMEOUT=60000

# Redis Configuration (캐싱용)
REDIS_HOST=localhost
REDIS_PORT=6379
REDIS_PASSWORD=
REDIS_DB=0

# JWT Configuration
JWT_SECRET=your_super_secret_jwt_key_here
JWT_EXPIRY=1h

# OAuth2 Configuration
OAUTH2_ACCESS_TOKEN_EXPIRY_HOURS=1
OAUTH2_REFRESH_TOKEN_EXPIRY_DAYS=30
OAUTH2_CODE_EXPIRY_MINUTES=10
OAUTH2_CODE_LENGTH=32

# Cache Configuration
CACHE_TTL=300000

# Cleanup Configuration
CLEANUP_CRON_EXPRESSION=0 0 * * *

# Application Configuration
PORT=3000
NODE_ENV=development
```

# JWT Configuration

```
JWT_SECRET=your_super_secret_jwt_key_here
JWT_EXPIRES_IN=1h
JWT_REFRESH_EXPIRES_IN=7d
```

# OAuth2 Token Expiry Configuration (선택사항)

```
OAUTH2_CODE_EXPIRY_MINUTES=10 # Authorization Code 만료 시간 (분)
OAUTH2_ACCESS_TOKEN_EXPIRY_HOURS=1 # Access Token 만료 시간 (시간)
OAUTH2_REFRESH_TOKEN_EXPIRY_DAYS=30 # Refresh Token 만료 시간 (일)
```

# Frontend Configuration (for CORS)

```
FRONTEND_URL=http://localhost:5173
```

## ✨ 주요 기능

### 🔐 OAuth2 인증 시스템

- Authorization Code Grant
- Refresh Token 지원
- PKCE (Proof Key for Code Exchange) 지원
- 다중 클라이언트 지원

### 🗄️ 데이터베이스 최적화

- **자동 정리**: 만료된 토큰과 인증 코드를 주기적으로 정리
- **스키마 최적화**: 데이터 타입 최적화 및 인덱스 추가
- **캐싱**: Redis를 활용한 토큰 검증 캐싱

### 🔧 설정 관리

- **중앙 집중식 설정**: 모든 설정을 환경변수로 관리
- **설정 검증**: 애플리케이션 시작 시 설정 유효성 검증
- **유연한 구성**: 기본값 제공으로 선택적 설정 가능

### 📊 모니터링 및 로깅

- 구조화된 로깅
- 정리 작업 결과 로깅
- 설정 검증 오류 보고

### 3. 데이터베이스 설정

```bash
# 데이터베이스 생성
mysql -u root -p
CREATE DATABASE flowauth;
EXIT;

# 마이그레이션 실행 (데이터베이스 스키마 생성)
npm run migration:run

# 초기 데이터 시딩 (필수 - OAuth2 시스템을 위한 기본 데이터)
npm run seed
```

#### 📋 시드 데이터 설명

`npm run seed` 명령어는 OAuth2 시스템 운영에 필요한 기본 데이터를 데이터베이스에 추가합니다:

**추가되는 데이터:**

- **OAuth2 스코프**: `read`, `write`, `profile`, `email`, `openid`, `offline_access`
- **기본 클라이언트**: 테스트용 OAuth2 클라이언트 (개발 환경용)
- **기본 사용자**: 관리자 계정 (선택사항)

**주의사항:**

- ✅ **필수 실행**: OAuth2 인증이 작동하려면 반드시 실행해야 합니다
- ✅ **안전성**: 기존 데이터에 영향을 주지 않고 추가만 수행합니다
- ✅ **재실행 가능**: 중복 실행해도 안전합니다

### 4. 개발 서버 실행

```bash
# 개발 모드 (핫 리로드)
npm run start:dev

# 프로덕션 모드
npm run build
npm run start:prod
```

서버가 `http://localhost:3000`에서 실행됩니다.

## 📚 API 문서

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

## 🗄️ 데이터베이스 스키마

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

## 🧪 테스트

```bash
# 단위 테스트 실행
npm run test

# 테스트 커버리지 확인
npm run test:cov

# E2E 테스트 실행
npm run test:e2e
```

## 📜 스크립트

```bash
# 코드 포맷팅
npm run format

# 린팅
npm run lint

# TypeORM CLI
npm run typeorm

# 마이그레이션 생성
npm run migration:generate -- src/migrations/MigrationName

# 마이그레이션 실행
npm run migration:run

# 마이그레이션 되돌리기
npm run migration:revert

# 데이터베이스 시딩 (OAuth2 기본 데이터 추가)
npm run seed
```

### 🚀 빠른 시작 가이드

프로젝트를 처음 설정할 때 다음 순서로 실행하세요:

```bash
# 1. 의존성 설치
npm install

# 2. 환경 변수 설정
cp .env.example .env
# .env 파일을 편집해서 데이터베이스 연결 정보 설정

# 3. 데이터베이스 생성
mysql -u root -p -e "CREATE DATABASE flowauth;"

# 4. 데이터베이스 스키마 생성
npm run migration:run

# 5. OAuth2 기본 데이터 추가 (필수)
npm run seed

# 6. 개발 서버 실행
npm run start:dev
```

**중요**: 5번 단계(`npm run seed`)를 건너뛰면 OAuth2 인증이 작동하지 않습니다.

## 🔧 문제 해결

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
2. MySQL 서비스가 실행 중인지 확인
3. 데이터베이스 권한 확인

### 마이그레이션 오류

**문제**: 마이그레이션 실행 실패

**해결 방법**:

1. 데이터베이스가 생성되어 있는지 확인
2. 이전 마이그레이션이 성공적으로 실행되었는지 확인
3. 마이그레이션 파일의 구문 오류 확인

## 🔒 보안 기능

- **JWT 토큰 기반 인증**
- **비밀번호 해싱 (bcrypt)**
- **헬멧 (Helmet) 보안 헤더**
- **CORS 설정**
- **레이트 리미팅**
- **PKCE (Proof Key for Code Exchange) 지원**
- **인가 코드 만료 (기본 10분)**
- **토큰 만료 관리**

## 🤝 기여하기

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## 📄 라이선스

This project is licensed under the MIT License.
