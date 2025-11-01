import {
  Controller,
  Post,
  Get,
  Delete,
  Body,
  UseGuards,
  Request,
  BadRequestException,
} from '@nestjs/common';
import {
  ApiTags,
  ApiOperation,
  ApiResponse,
  ApiBearerAuth,
} from '@nestjs/swagger';
import { TwoFactorService } from './two-factor.service';
import { JwtAuthGuard } from './jwt-auth.guard';
import { TWO_FACTOR_CONSTANTS } from '../constants/auth.constants';
import {
  VerifyTwoFactorDto,
  DisableTwoFactorDto,
  TwoFactorResponseDto,
  BackupCodeDto,
} from './dto/2fa/two-factor.dto';

interface RequestWithUser {
  user: {
    id: number;
    permissions?: number;
  };
}

@ApiTags('Authentication')
@Controller('auth/2fa')
@UseGuards(JwtAuthGuard)
@ApiBearerAuth()
export class TwoFactorController {
  constructor(private readonly twoFactorService: TwoFactorService) {}

  @Post('setup')
  @ApiOperation({ summary: '2FA 설정을 위한 시크릿 생성' })
  @ApiResponse({
    status: 200,
    description: '2FA 설정 정보',
    type: TwoFactorResponseDto,
  })
  @ApiResponse({ status: 400, description: '2FA가 이미 활성화됨' })
  async setupTwoFactor(
    @Request() req: RequestWithUser,
  ): Promise<TwoFactorResponseDto> {
    return this.twoFactorService.generateSecret(req.user.id);
  }

  @Post('enable')
  @ApiOperation({ summary: '2FA 활성화' })
  @ApiResponse({ status: 200, description: '2FA가 성공적으로 활성화됨' })
  @ApiResponse({ status: 400, description: '잘못된 토큰 또는 이미 활성화됨' })
  async enableTwoFactor(
    @Request() req: RequestWithUser,
    @Body() body: { token: string; secret: string; backupCodes: string[] },
  ): Promise<{ message: string }> {
    const { token, secret, backupCodes } = body;

    if (
      !token ||
      !secret ||
      !backupCodes ||
      backupCodes.length !== TWO_FACTOR_CONSTANTS.BACKUP_CODE_COUNT
    ) {
      throw new BadRequestException(
        `토큰, 시크릿, 백업 코드(${TWO_FACTOR_CONSTANTS.BACKUP_CODE_COUNT}개)가 모두 필요합니다.`,
      );
    }

    await this.twoFactorService.enableTwoFactor(
      req.user.id,
      token,
      secret,
      backupCodes,
    );

    return { message: '2FA가 성공적으로 활성화되었습니다.' };
  }

  @Post('verify')
  @ApiOperation({ summary: '2FA 토큰 검증' })
  @ApiResponse({ status: 200, description: '토큰 검증 성공' })
  @ApiResponse({ status: 400, description: '잘못된 토큰' })
  async verifyTwoFactor(
    @Request() req: RequestWithUser,
    @Body() verifyDto: VerifyTwoFactorDto,
  ): Promise<{ valid: boolean }> {
    const isValid = await this.twoFactorService.verifyToken(
      req.user.id,
      verifyDto.token,
    );

    if (!isValid) {
      throw new BadRequestException('잘못된 2FA 토큰입니다.');
    }

    return { valid: true };
  }

  @Post('verify-backup')
  @ApiOperation({ summary: '백업 코드 검증' })
  @ApiResponse({ status: 200, description: '백업 코드 검증 성공' })
  @ApiResponse({ status: 400, description: '잘못된 백업 코드' })
  async verifyBackupCode(
    @Request() req: RequestWithUser,
    @Body() backupCodeDto: BackupCodeDto,
  ): Promise<{ valid: boolean }> {
    const isValid = await this.twoFactorService.verifyBackupCode(
      req.user.id,
      backupCodeDto.code,
    );

    if (!isValid) {
      throw new BadRequestException('잘못된 백업 코드입니다.');
    }

    return { valid: true };
  }

  @Delete('disable')
  @ApiOperation({ summary: '2FA 비활성화' })
  @ApiResponse({ status: 200, description: '2FA가 성공적으로 비활성화됨' })
  @ApiResponse({
    status: 400,
    description: '잘못된 비밀번호 또는 2FA가 활성화되지 않음',
  })
  async disableTwoFactor(
    @Request() req: RequestWithUser,
    @Body() disableDto: DisableTwoFactorDto,
  ): Promise<{ message: string }> {
    await this.twoFactorService.disableTwoFactor(
      req.user.id,
      disableDto.currentPassword,
    );

    return { message: '2FA가 성공적으로 비활성화되었습니다.' };
  }

  @Get('status')
  @ApiOperation({ summary: '2FA 상태 확인' })
  @ApiResponse({
    status: 200,
    description: '2FA 상태 정보',
    schema: {
      type: 'object',
      properties: {
        enabled: { type: 'boolean' },
        hasBackupCodes: { type: 'boolean' },
      },
    },
  })
  async getTwoFactorStatus(@Request() req: RequestWithUser): Promise<{
    enabled: boolean;
    hasBackupCodes: boolean;
  }> {
    return this.twoFactorService.getTwoFactorStatus(req.user.id);
  }
}
