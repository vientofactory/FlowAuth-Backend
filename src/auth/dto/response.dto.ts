import { ApiProperty } from '@nestjs/swagger';

/**
 * 사용자 정보 DTO
 */
export class UserDto {
  @ApiProperty({
    description: '사용자 ID',
    example: 1,
  })
  id: number;

  @ApiProperty({
    description: '사용자명',
    example: 'john_doe',
  })
  username: string;

  @ApiProperty({
    description: '이메일 주소',
    example: 'john@example.com',
  })
  email: string;

  @ApiProperty({
    description: '이름',
    example: 'John',
    required: false,
  })
  firstName?: string;

  @ApiProperty({
    description: '성',
    example: 'Doe',
    required: false,
  })
  lastName?: string;
}

/**
 * 로그인 응답 DTO
 */
export class LoginResponseDto {
  @ApiProperty({
    description: '사용자 정보',
    type: UserDto,
  })
  user: UserDto;

  @ApiProperty({
    description: 'JWT 액세스 토큰',
    example: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...',
  })
  accessToken: string;
}

/**
 * 클라이언트 생성 응답 DTO
 */
export class ClientCreateResponseDto {
  @ApiProperty({
    description: '클라이언트 ID',
    example: 1,
  })
  id: number;

  @ApiProperty({
    description: '클라이언트 식별자',
    example: 'my-client-app',
  })
  clientId: string;

  @ApiProperty({
    description: '클라이언트 시크릿',
    example: 'generated-secret-key',
    required: false,
  })
  clientSecret?: string;

  @ApiProperty({
    description: '클라이언트 이름',
    example: 'My Application',
  })
  name: string;

  @ApiProperty({
    description: '클라이언트 설명',
    example: 'A sample OAuth2 client application',
    required: false,
  })
  description?: string;

  @ApiProperty({
    description: '생성 날짜',
    example: '2023-12-01T10:30:00Z',
  })
  createdAt: Date;
}

/**
 * 클라이언트 목록 아이템 DTO
 */
export class ClientListItemDto {
  @ApiProperty({
    description: '클라이언트 ID',
    example: 1,
  })
  id: number;

  @ApiProperty({
    description: '클라이언트 식별자',
    example: 'my-client-app',
  })
  clientId: string;

  @ApiProperty({
    description: '클라이언트 이름',
    example: 'My Application',
  })
  name: string;

  @ApiProperty({
    description: '활성 상태',
    example: true,
  })
  isActive: boolean;

  @ApiProperty({
    description: '생성 날짜',
    example: '2023-12-01T10:30:00Z',
  })
  createdAt: Date;

  @ApiProperty({
    description: '마지막 수정 날짜',
    example: '2023-12-05T15:20:00Z',
  })
  updatedAt: Date;
}

/**
 * 클라이언트 목록 응답 DTO
 */
export class ClientListResponseDto {
  @ApiProperty({
    description: '클라이언트 목록',
    type: [ClientListItemDto],
  })
  clients: ClientListItemDto[];

  @ApiProperty({
    description: '총 개수',
    example: 5,
  })
  total: number;
}

/**
 * 클라이언트 시크릿 리셋 응답 DTO
 */
export class ClientSecretResetResponseDto {
  @ApiProperty({
    description: '새로운 클라이언트 시크릿',
    example: 'new-generated-secret-key',
  })
  clientSecret: string;

  @ApiProperty({
    description: '성공 메시지',
    example: 'Client secret has been reset successfully',
  })
  message: string;
}
