import {
  Controller,
  Get,
  Param,
  Post,
  Res,
  UploadedFile,
  UseGuards,
  UseInterceptors,
  Logger,
} from '@nestjs/common';
import { FileInterceptor } from '@nestjs/platform-express';
import {
  ApiTags,
  ApiOperation,
  ApiResponse,
  ApiConsumes,
  ApiBody,
  ApiBearerAuth,
  ApiParam,
} from '@nestjs/swagger';
import type { Response } from 'express';
import { FileUploadService } from './file-upload.service';
import type { MulterFile } from './types';
import { UPLOAD_CONFIG } from './config';
import { UPLOAD_ERRORS } from './types';
import { JwtAuthGuard } from '../auth/jwt-auth.guard';
import {
  PermissionsGuard,
  RequirePermissions,
} from '../auth/permissions.guard';
import { PERMISSIONS } from '../constants/auth.constants';
import { FileUploadResponseDto } from './dto/response.dto';
import { isValidFilename, validateFileEnhanced } from './validators';

/**
 * 로고 업로드 설정 정보를 가져오는 헬퍼 함수
 */
function getLogoUploadInfo() {
  const logoConfig = UPLOAD_CONFIG.fileTypes.logo;
  const imageProcessing = UPLOAD_CONFIG.imageProcessing;

  // 지원 파일 형식 (대문자로 변환)
  const supportedFormats = logoConfig.allowedMimes
    .map((mime) => mime.split('/')[1]?.toUpperCase())
    .filter(Boolean)
    .join(', ');

  // 최대 크기 (MB 단위로 변환)
  const maxSizeMB = (logoConfig.maxSize / (1024 * 1024)).toFixed(1);

  // 권장 크기 및 비율 정보
  const recommendedSize = imageProcessing.defaultSize;
  const aspectRatio = `${recommendedSize.width}:${recommendedSize.height}`;

  return {
    supportedFormats,
    maxSizeMB,
    recommendedWidth: recommendedSize.width,
    recommendedHeight: recommendedSize.height,
    aspectRatio,
    resizeFit: imageProcessing.resizeOptions.fit,
    resizePosition: imageProcessing.resizeOptions.position,
  };
}

@Controller('uploads')
@ApiTags('File Upload')
export class UploadController {
  private readonly logger = new Logger(UploadController.name);

  constructor(private readonly fileUploadService: FileUploadService) {}

  @Post('logo')
  @UseGuards(JwtAuthGuard, PermissionsGuard)
  @RequirePermissions(PERMISSIONS.UPLOAD_FILE)
  @UseInterceptors(FileInterceptor('logo'))
  @ApiBearerAuth('JWT-auth')
  @ApiOperation({
    summary: '로고 파일 업로드',
    description: (() => {
      const info = getLogoUploadInfo();
      return `
클라이언트 애플리케이션의 로고 파일을 업로드합니다.

**지원 파일 형식:**
- ${info.supportedFormats}
- 최대 크기: ${info.maxSizeMB}MB

**권장 사항:**
- 권장 크기: ${info.recommendedWidth}x${info.recommendedHeight} 픽셀
- 권장 비율: ${info.aspectRatio}
- 리사이징 방식: ${info.resizeFit} (${info.resizePosition} 기준)

**업로드된 파일:**
- 고유한 파일명으로 저장
- 공개 URL 제공
- 자동 최적화 적용 (WebP/AVIF 우선)
      `;
    })(),
  })
  @ApiConsumes('multipart/form-data')
  @ApiBody({
    description: '업로드할 로고 파일',
    schema: {
      type: 'object',
      properties: {
        logo: {
          type: 'string',
          format: 'binary',
          description: '로고 이미지 파일',
        },
      },
      required: ['logo'],
    },
  })
  @ApiResponse({
    status: 201,
    description: '파일 업로드 성공',
    type: FileUploadResponseDto,
  })
  @ApiResponse({
    status: 400,
    description: '잘못된 파일 또는 파일 없음',
  })
  @ApiResponse({
    status: 401,
    description: '인증 필요',
  })
  async uploadLogo(
    @UploadedFile() file: MulterFile,
  ): Promise<FileUploadResponseDto> {
    if (!file) {
      throw UPLOAD_ERRORS.NO_FILE_UPLOADED;
    }

    // Enhanced file validation with content type security
    const validationResult = await validateFileEnhanced(file, 'logo', {
      enableContentValidation: true,
    });

    if (!validationResult.isValid) {
      this.logger.error({
        message: 'File validation failed',
        errors: validationResult.errors,
        filename: file.originalname,
        mimetype: file.mimetype,
        size: file.size,
      });
      throw new Error(
        `File validation failed: ${validationResult.errors.join(', ')}`,
      );
    }

    // Log warnings if any
    if (validationResult.warnings.length > 0) {
      this.logger.warn({
        message: 'File validation warnings found',
        warnings: validationResult.warnings,
        filename: file.originalname,
      });
    }

    // Process logo image with Sharp for optimization
    const logoUrl = await this.fileUploadService.processLogoImage(file);
    const filename =
      typeof logoUrl === 'string' ? (logoUrl.split('/').pop() ?? '') : '';

    return {
      success: true,
      message: 'Logo uploaded successfully',
      data: {
        filename,
        url: logoUrl,
        originalName: file.originalname,
        size: file.size,
        mimetype: file.mimetype,
      },
    };
  }

  @Get('logos/:filename')
  @UseGuards(JwtAuthGuard, PermissionsGuard)
  @RequirePermissions(PERMISSIONS.UPLOAD_FILE)
  @ApiBearerAuth('JWT-auth')
  @ApiOperation({
    summary: '로고 파일 조회',
    description: '업로드된 로고 파일을 조회합니다.',
  })
  @ApiParam({
    name: 'filename',
    description: '조회할 파일명',
    example: '550e8400-e29b-41d4-a716-446655440000.webp',
  })
  @ApiResponse({
    status: 200,
    description: '파일 반환',
    content: {
      'image/*': {
        schema: {
          type: 'string',
          format: 'binary',
        },
      },
    },
  })
  @ApiResponse({
    status: 401,
    description: '인증 필요',
  })
  @ApiResponse({
    status: 404,
    description: '파일을 찾을 수 없음',
  })
  getLogo(@Param('filename') filename: string, @Res() res: Response) {
    // Validate filename to prevent directory traversal and invalid characters
    if (!isValidFilename(filename)) {
      throw UPLOAD_ERRORS.INVALID_FILE_TYPE;
    }

    const filePath = this.fileUploadService.getFullFilePath('logo', filename);

    // Check if file exists
    if (!this.fileUploadService.fileExists('logo', filename)) {
      throw UPLOAD_ERRORS.FILE_NOT_FOUND;
    }

    // Set appropriate headers for caching
    res.setHeader('Content-Type', 'image/*');
    res.setHeader('Cache-Control', UPLOAD_CONFIG.cache.cacheControl);

    // Send file
    res.sendFile(filePath, (error) => {
      if (error) {
        throw UPLOAD_ERRORS.UPLOAD_FAILED;
      }
    });
  }

  @Get('config/:type')
  @UseGuards(JwtAuthGuard, PermissionsGuard)
  @RequirePermissions(PERMISSIONS.UPLOAD_FILE)
  @ApiBearerAuth('JWT-auth')
  @ApiOperation({
    summary: '업로드 설정 조회',
    description: '파일 타입별 업로드 설정 정보를 조회합니다.',
  })
  @ApiParam({
    name: 'type',
    description: '파일 타입',
    example: 'logo',
    enum: ['logo'],
  })
  @ApiResponse({
    status: 200,
    description: '업로드 설정 정보',
    schema: {
      type: 'object',
      properties: {
        allowedMimes: {
          type: 'array',
          items: { type: 'string' },
          description: '허용된 MIME 타입',
          example: ['image/jpeg', 'image/png', 'image/webp'],
        },
        maxSize: {
          type: 'number',
          description: '최대 파일 크기 (bytes)',
          example: 5242880,
        },
        maxSizeMB: {
          type: 'number',
          description: '최대 파일 크기 (MB)',
          example: 5,
        },
        destination: {
          type: 'string',
          description: '저장 경로',
          example: 'uploads/logos',
        },
      },
    },
  })
  @ApiResponse({
    status: 401,
    description: '인증 필요',
  })
  @ApiResponse({
    status: 404,
    description: '지원하지 않는 파일 타입',
  })
  getUploadConfig(@Param('type') type: string) {
    const config =
      UPLOAD_CONFIG.fileTypes[type as keyof typeof UPLOAD_CONFIG.fileTypes];

    if (!config) {
      throw new Error(`Upload configuration for type '${type}' not found`);
    }

    // 이미지 타입인 경우 추가 최적화 정보 제공
    const isImageType = type === 'logo' || type === 'avatar';
    const imageProcessing = isImageType ? UPLOAD_CONFIG.imageProcessing : null;

    const baseConfig = {
      allowedMimes: config.allowedMimes,
      maxSize: config.maxSize,
      maxSizeMB: Math.round((config.maxSize / (1024 * 1024)) * 100) / 100,
      destination: config.destination,
    };

    if (imageProcessing) {
      return {
        ...baseConfig,
        // 지원 파일 형식 (대문자로 변환)
        supportedFormats: (config.allowedMimes as readonly string[])
          .map((mime: string) => mime.split('/')[1]?.toUpperCase())
          .filter(Boolean)
          .join(', '),
        // 권장 크기 및 비율 정보
        recommendedSize: {
          width: imageProcessing.defaultSize.width,
          height: imageProcessing.defaultSize.height,
        },
        aspectRatio: `${imageProcessing.defaultSize.width}:${imageProcessing.defaultSize.height}`,
        resizeFit: imageProcessing.resizeOptions.fit,
        resizePosition: imageProcessing.resizeOptions.position,
        // 최적화 정보
        optimization: {
          outputFormats: imageProcessing.outputFormats,
          quality: {
            jpeg: imageProcessing.formatOptions.jpeg.quality,
            webp: imageProcessing.formatOptions.webp.quality,
            avif: imageProcessing.formatOptions.avif.quality,
          },
        },
      };
    }

    return baseConfig;
  }
}
