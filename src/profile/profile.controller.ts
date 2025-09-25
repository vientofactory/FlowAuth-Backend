import {
  Controller,
  Get,
  Put,
  Body,
  Request,
  UseGuards,
  Param,
  Post,
  UseInterceptors,
  UploadedFile,
  Delete,
} from '@nestjs/common';
import {
  ApiTags,
  ApiOperation,
  ApiResponse,
  ApiBearerAuth,
  ApiBody,
  ApiConsumes,
} from '@nestjs/swagger';
import { FileInterceptor } from '@nestjs/platform-express';
import { ProfileService } from './profile.service';
import { JwtAuthGuard } from '../auth/jwt-auth.guard';
import type { AuthenticatedRequest } from '../types/auth.types';
import { User } from '../user/user.entity';

@Controller('profile')
@ApiTags('Profile')
export class ProfileController {
  constructor(private readonly profileService: ProfileService) {}

  @Get()
  @UseGuards(JwtAuthGuard)
  @ApiBearerAuth()
  @ApiOperation({ summary: '사용자 프로필 조회' })
  @ApiResponse({
    status: 200,
    description: '프로필 정보 반환',
    type: User,
  })
  @ApiResponse({
    status: 401,
    description: '인증되지 않은 사용자',
  })
  async getProfile(@Request() req: AuthenticatedRequest): Promise<User> {
    return this.profileService.findById(req.user.id);
  }

  @Put()
  @UseGuards(JwtAuthGuard)
  @ApiBearerAuth()
  @ApiOperation({ summary: '사용자 프로필 업데이트' })
  @ApiResponse({
    status: 200,
    description: '프로필 업데이트 성공',
    type: User,
  })
  @ApiResponse({
    status: 400,
    description: '잘못된 요청 데이터',
  })
  @ApiResponse({
    status: 401,
    description: '인증되지 않은 사용자',
  })
  @ApiBody({
    schema: {
      type: 'object',
      properties: {
        firstName: { type: 'string', example: 'John' },
        lastName: { type: 'string', example: 'Doe' },
        username: { type: 'string', example: 'john_doe' },
      },
    },
  })
  async updateProfile(
    @Request() req: AuthenticatedRequest,
    @Body()
    updateData: Partial<{
      firstName: string;
      lastName: string;
      username: string;
    }>,
  ): Promise<User> {
    return this.profileService.updateProfile(req.user.id, updateData);
  }

  @Put('password')
  @UseGuards(JwtAuthGuard)
  @ApiBearerAuth()
  @ApiOperation({ summary: '비밀번호 변경' })
  @ApiResponse({
    status: 200,
    description: '비밀번호 변경 성공',
  })
  @ApiResponse({
    status: 400,
    description: '잘못된 요청 데이터',
  })
  @ApiResponse({
    status: 401,
    description: '인증되지 않은 사용자',
  })
  @ApiResponse({
    status: 403,
    description: '현재 비밀번호가 일치하지 않음',
  })
  @ApiBody({
    schema: {
      type: 'object',
      properties: {
        currentPassword: { type: 'string', example: 'currentPassword123' },
        newPassword: { type: 'string', example: 'newPassword123' },
      },
      required: ['currentPassword', 'newPassword'],
    },
  })
  async changePassword(
    @Request() req: AuthenticatedRequest,
    @Body() passwordData: { currentPassword: string; newPassword: string },
  ): Promise<{ message: string }> {
    await this.profileService.changePassword(
      req.user.id,
      passwordData.currentPassword,
      passwordData.newPassword,
    );
    return { message: '비밀번호가 성공적으로 변경되었습니다.' };
  }

  @Get('check-username/:username')
  @UseGuards(JwtAuthGuard)
  @ApiBearerAuth()
  @ApiOperation({ summary: '사용자명 중복 체크' })
  @ApiResponse({
    status: 200,
    description: '사용자명 사용 가능 여부 반환',
    schema: {
      type: 'object',
      properties: {
        available: { type: 'boolean', example: true },
        message: { type: 'string', example: '사용 가능한 사용자명입니다.' },
      },
    },
  })
  @ApiResponse({
    status: 401,
    description: '인증되지 않은 사용자',
  })
  async checkUsername(
    @Param('username') username: string,
    @Request() req: AuthenticatedRequest,
  ): Promise<{ available: boolean; message: string }> {
    return this.profileService.checkUsernameAvailability(username, req.user.id);
  }

  @Post('avatar')
  @UseGuards(JwtAuthGuard)
  @UseInterceptors(FileInterceptor('avatar'))
  @ApiBearerAuth()
  @ApiOperation({ summary: '프로필 아바타 업로드' })
  @ApiConsumes('multipart/form-data')
  @ApiBody({
    schema: {
      type: 'object',
      properties: {
        avatar: {
          type: 'string',
          format: 'binary',
          description: '업로드할 아바타 이미지 파일',
        },
      },
    },
  })
  @ApiResponse({
    status: 200,
    description: '아바타 업로드 성공',
    schema: {
      type: 'object',
      properties: {
        avatarUrl: {
          type: 'string',
          example: '/uploads/avatars/avatar_1_1234567890.png',
        },
        message: {
          type: 'string',
          example: '아바타가 성공적으로 업로드되었습니다.',
        },
      },
    },
  })
  @ApiResponse({
    status: 400,
    description: '잘못된 파일 형식 또는 크기 초과',
  })
  @ApiResponse({
    status: 401,
    description: '인증되지 않은 사용자',
  })
  async uploadAvatar(
    @Request() req: AuthenticatedRequest,
    @UploadedFile() file: Express.Multer.File,
  ): Promise<{ avatarUrl: string; message: string }> {
    const avatarUrl = await this.profileService.uploadAvatar(req.user.id, file);
    return {
      avatarUrl,
      message: '아바타가 성공적으로 업로드되었습니다.',
    };
  }

  @Delete('avatar')
  @UseGuards(JwtAuthGuard)
  @ApiBearerAuth()
  @ApiOperation({ summary: '프로필 아바타 제거' })
  @ApiResponse({
    status: 200,
    description: '아바타 제거 성공',
    schema: {
      type: 'object',
      properties: {
        message: {
          type: 'string',
          example: '아바타가 성공적으로 제거되었습니다.',
        },
      },
    },
  })
  @ApiResponse({
    status: 401,
    description: '인증되지 않은 사용자',
  })
  async removeAvatar(
    @Request() req: AuthenticatedRequest,
  ): Promise<{ message: string }> {
    await this.profileService.removeAvatar(req.user.id);
    return {
      message: '아바타가 성공적으로 제거되었습니다.',
    };
  }
}
