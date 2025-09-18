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
