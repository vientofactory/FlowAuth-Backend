import { ApiProperty } from '@nestjs/swagger';

/**
 * 기본 API 응답 DTO
 */
export class ApiResponseDto {
  @ApiProperty({
    description: '요청 성공 여부',
    example: true,
  })
  success: boolean;

  @ApiProperty({
    description: '응답 메시지',
    example: 'Request completed successfully',
  })
  message: string;
}

/**
 * 서버 상태 응답 DTO
 */
export class ServerStatusResponseDto {
  @ApiProperty({
    description: '서버 상태 메시지',
    example: 'FlowAuth API is running!',
  })
  message: string;
}

/**
 * 리다이렉트 URL 응답 DTO
 */
export class RedirectUrlResponseDto {
  @ApiProperty({
    description: '리다이렉트 URL',
    example: 'https://client.example.com/callback?code=abc123&state=xyz789',
  })
  redirect_url: string;
}

/**
 * 에러 응답 DTO
 */
export class ErrorResponseDto {
  @ApiProperty({
    description: '에러 코드',
    example: 'invalid_request',
  })
  error: string;

  @ApiProperty({
    description: '에러 설명',
    example: 'The request is missing a required parameter',
  })
  error_description?: string;

  @ApiProperty({
    description: '상태 값 (OAuth2 요청인 경우)',
    example: 'xyz789',
    required: false,
  })
  state?: string;
}

/**
 * RFC 7807 Problem Details 응답 DTO
 */
export class ProblemDetailsDto {
  @ApiProperty({
    description: '문제 타입 URI',
    example: 'https://tools.ietf.org/html/rfc7807#section-3.1',
  })
  type: string;

  @ApiProperty({
    description: '문제의 간단한 설명',
    example: 'Bad Request',
  })
  title: string;

  @ApiProperty({
    description: '문제의 자세한 설명',
    example: 'The request is missing a required parameter',
    required: false,
  })
  detail?: string;

  @ApiProperty({
    description: 'HTTP 상태 코드',
    example: 400,
  })
  status: number;

  @ApiProperty({
    description: '문제 인스턴스 URI',
    example: '/oauth2/token',
    required: false,
  })
  instance?: string;

  @ApiProperty({
    description: '추가 확장 필드',
    example: {
      error: 'invalid_request',
      error_description: 'Missing required parameter',
    },
    required: false,
  })
  extensions?: Record<string, unknown>;
}

/**
 * 표준 API 성공 응답 DTO
 */
export class StandardApiResponseDto<T = unknown> {
  @ApiProperty({
    description: '요청 성공 여부',
    example: true,
  })
  success: boolean;

  @ApiProperty({
    description: '응답 메시지',
    example: 'Request completed successfully',
  })
  message: string;

  @ApiProperty({
    description: '응답 데이터',
  })
  data: T;

  @ApiProperty({
    description: '응답 타임스탬프',
    example: '2023-12-01T10:30:00Z',
    required: false,
  })
  timestamp?: string;
}
