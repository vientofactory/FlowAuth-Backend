import { Controller, Get, Put, Body, Request, UseGuards } from '@nestjs/common';
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
      },
    },
  })
  async updateProfile(
    @Request() req: AuthenticatedRequest,
    @Body() updateData: Partial<{ firstName: string; lastName: string }>,
  ): Promise<User> {
    return this.profileService.updateProfile(req.user.id, updateData);
  }
}
