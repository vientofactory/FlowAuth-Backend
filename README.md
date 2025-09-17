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

## 🛠️ 빠른 시작

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
# 데이터베이스 생성
mysql -u root -p -e "CREATE DATABASE flowauth;"

# 마이그레이션 실행
npm run migration:run

# 초기 데이터 시딩 (OAuth2 기본 데이터)
npm run seed
```

### 4. 개발 서버 실행

```bash
npm run start:dev
```

서버가 `http://localhost:3000`에서 실행됩니다.

## 📚 API 문서

### Swagger UI

API 문서를 확인하려면 브라우저에서 `http://localhost:3000/api`로 접속하세요.

### 주요 엔드포인트

#### 🔐 인증 관련

- `POST /auth/login` - 사용자 로그인
- `POST /auth/register` - 사용자 등록
- `GET /auth/profile` - 프로필 조회

#### 🔄 OAuth2 관련

- `GET /oauth2/authorize` - 인가 요청
- `POST /oauth2/token` - 토큰 발급
- `GET /oauth2/userinfo` - 사용자 정보 조회
- `POST /oauth2/authorize/consent` - 동의 처리

#### 🏢 클라이언트 관리

- `GET /clients` - 클라이언트 목록 조회
- `POST /clients` - 새 클라이언트 생성
- `PUT /clients/:id` - 클라이언트 수정
- `DELETE /clients/:id` - 클라이언트 삭제

## 🗄️ 데이터베이스 스키마

### 주요 엔티티

#### 👤 User (사용자)

```sql
- id: number (Primary Key)
- email: string (Unique)
- username: string (Unique)
- password: string (Hashed)
- roles: string[] (JSON Array)
- createdAt: Date
- updatedAt: Date
```

#### 🏢 Client (OAuth2 클라이언트)

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

#### 🔄 AuthorizationCode (인가 코드)

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

#### 🎫 Token (액세스 토큰)

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

## ⚙️ 환경 설정

### 추가 환경 변수 (선택사항)

```env
# Redis Configuration (캐싱용)
REDIS_HOST=localhost
REDIS_PORT=6379
REDIS_PASSWORD=
REDIS_DB=0

# OAuth2 Configuration
OAUTH2_ACCESS_TOKEN_EXPIRY_HOURS=1
OAUTH2_REFRESH_TOKEN_EXPIRY_DAYS=30
OAUTH2_CODE_EXPIRY_MINUTES=10
OAUTH2_CODE_LENGTH=32

# Cache Configuration
CACHE_TTL=300000

# Cleanup Configuration
CLEANUP_CRON_EXPRESSION=0 0 * * *

# Frontend Configuration (for CORS)
FRONTEND_URL=http://localhost:5173
```

## 🔒 보안 기능

- **JWT 토큰 기반 인증**
- **비밀번호 해싱 (bcrypt)**
- **헬멧 (Helmet) 보안 헤더**
- **CORS 설정**
- **레이트 리미팅**
- **PKCE (Proof Key for Code Exchange) 지원**
- **인가 코드 만료 (기본 10분)**
- **토큰 만료 관리**

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

## 🤝 기여하기

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## 📄 라이선스

This project is licensed under the MIT License.
