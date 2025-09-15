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

# Application Configuration
PORT=3000
NODE_ENV=development

# JWT Configuration
JWT_SECRET=your_super_secret_jwt_key_here
JWT_EXPIRES_IN=1h
JWT_REFRESH_EXPIRES_IN=7d

# OAuth2 Token Expiry Configuration (선택사항)
OAUTH2_CODE_EXPIRY_MINUTES=10          # Authorization Code 만료 시간 (분)
OAUTH2_ACCESS_TOKEN_EXPIRY_HOURS=1     # Access Token 만료 시간 (시간)
OAUTH2_REFRESH_TOKEN_EXPIRY_DAYS=30    # Refresh Token 만료 시간 (일)

# Frontend Configuration (for CORS)
FRONTEND_URL=http://localhost:5173
```

### 3. 데이터베이스 설정

```bash
# 데이터베이스 생성
mysql -u root -p
CREATE DATABASE flowauth;
EXIT;

# 마이그레이션 실행
npm run migration:run

# 초기 데이터 시딩 (선택사항)
npm run seed
```

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

## 🤝 기여하기

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## 📄 라이선스

This project is licensed under the MIT License.

### 3. 데이터베이스 설정

MySQL 데이터베이스를 생성하세요:

```sql
CREATE DATABASE flowauth;
```

### 4. 개발 서버 실행

```bash
# 개발 모드 (핫 리로드)
npm run start:dev

# 프로덕션 모드
npm run start:prod
```

서버가 `http://localhost:3000`에서 실행됩니다.

## 📚 API 문서

서버 실행 후 다음 엔드포인트에서 API 문서를 확인할 수 있습니다:

- **Swagger UI**: `http://localhost:3000/api`

## 🧪 테스트

```bash
# 단위 테스트
npm run test

# e2e 테스트
npm run test:e2e

# 테스트 커버리지
npm run test:cov
```

## 🏗 프로젝트 구조

```
src/
├── app.module.ts              # 메인 애플리케이션 모듈
├── main.ts                    # 애플리케이션 진입점
├── database/                  # 데이터베이스 설정 모듈
│   └── database.module.ts
├── auth/                      # 인증 관련 모듈
│   ├── auth.module.ts
│   ├── auth.service.ts
│   ├── auth.controller.ts
│   └── dto/
├── user/                      # 사용자 엔티티
│   └── user.entity.ts
├── client/                    # OAuth2 클라이언트 엔티티
│   └── client.entity.ts
├── token/                     # 토큰 엔티티
│   └── token.entity.ts
├── authorization-code/        # 인가 코드 엔티티
│   └── authorization-code.entity.ts
└── ...
```

## 🔧 주요 기능

### 사용자 관리

- 사용자 등록/로그인
- 프로필 관리
- 비밀번호 해싱 (bcrypt)

### OAuth2 클라이언트 관리

- 클라이언트 등록
- 클라이언트 정보 조회/수정/삭제
- 자동 clientId/clientSecret 생성

### 보안 기능

- JWT 토큰 기반 인증
- CORS 설정
- 헬멧 보안 미들웨어
- 입력 검증 및 sanitization

## 📡 API 엔드포인트

### 인증 관련

- `POST /auth/register` - 사용자 등록
- `POST /auth/login` - 사용자 로그인

### 클라이언트 관리

- `POST /auth/clients` - OAuth2 클라이언트 등록
- `GET /auth/clients` - 클라이언트 목록 조회
- `GET /auth/clients/:id` - 특정 클라이언트 조회

## 🔒 보안 고려사항

- 프로덕션 환경에서는 `synchronize: false`로 설정
- 강력한 JWT 시크릿 사용
- HTTPS 사용 권장
- Rate limiting 적용

## 🤝 기여하기

1. 이 리포지토리를 포크하세요
2. 기능 브랜치를 생성하세요 (`git checkout -b feature/AmazingFeature`)
3. 변경사항을 커밋하세요 (`git commit -m 'Add some AmazingFeature'`)
4. 브랜치에 푸시하세요 (`git push origin feature/AmazingFeature`)
5. Pull Request를 생성하세요

## 📄 라이선스

이 프로젝트는 MIT 라이선스 하에 있습니다.
