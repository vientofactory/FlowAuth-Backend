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
DB_HOST=localhost
DB_PORT=3306
DB_USERNAME=root
DB_PASSWORD=your_password
DB_NAME=flowauth

JWT_SECRET=your_jwt_secret
PORT=3000
```

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
