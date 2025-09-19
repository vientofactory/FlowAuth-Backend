import {
  Controller,
  Get,
  Put,
  Body,
  Request,
  UseGuards,
  Param,
} from '@nestjs/common';
import {
  ApiTags,
  ApiOperation,
  ApiResponse,
  ApiBearerAuth,
  ApiBody,
} from '@nestjs/swagger';
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
}
