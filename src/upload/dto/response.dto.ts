import { ApiProperty } from '@nestjs/swagger';

/**
 * 파일 정보 DTO
 */
export class FileInfoDto {
  @ApiProperty({
    description: '파일 이름',
    example: 'abc123-logo.png',
  })
  filename: string;

  @ApiProperty({
    description: '업로드된 파일의 URL',
    example: '/uploads/logos/abc123-logo.png',
  })
  url: string;

  @ApiProperty({
    description: '원본 파일 이름',
    example: 'my-company-logo.png',
  })
  originalName: string;

  @ApiProperty({
    description: '파일 크기 (바이트)',
    example: 15420,
  })
  size: number;

  @ApiProperty({
    description: 'MIME 타입',
    example: 'image/png',
  })
  mimetype: string;
}

/**
 * 파일 업로드 응답 DTO
 */
export class FileUploadResponseDto {
  @ApiProperty({
    description: '업로드 성공 여부',
    example: true,
  })
  success: boolean;

  @ApiProperty({
    description: '응답 메시지',
    example: 'Logo uploaded successfully',
  })
  message: string;

  @ApiProperty({
    description: '업로드된 파일 정보',
    type: FileInfoDto,
  })
  data: FileInfoDto;
}

/**
 * 업로드 설정 응답 DTO
 */
export class UploadConfigResponseDto {
  @ApiProperty({
    description: '최대 파일 크기 (바이트)',
    example: 5242880,
  })
  maxFileSize: number;

  @ApiProperty({
    description: '허용된 파일 타입',
    example: ['image/jpeg', 'image/png', 'image/webp'],
    type: [String],
  })
  allowedMimeTypes: string[];

  @ApiProperty({
    description: '허용된 파일 확장자',
    example: ['.jpg', '.jpeg', '.png', '.webp'],
    type: [String],
  })
  allowedExtensions: string[];
}
