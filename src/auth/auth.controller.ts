import {
  Controller,
  Post,
  Body,
  Get,
  Param,
  Put,
  Request,
  Patch,
  Delete,
  UseGuards,
  Res,
  BadRequestException,
} from '@nestjs/common';
import {
  ApiTags,
  ApiOperation,
  ApiResponse,
  ApiBody,
  ApiBearerAuth,
} from '@nestjs/swagger';
import { ThrottlerGuard, Throttle } from '@nestjs/throttler';
import type { Response, Request as ExpressRequest } from 'express';
import { AuthService } from './auth.service';
import { CreateUserDto } from './dto/create-user.dto';
import { LoginDto } from './dto/login.dto';
import { CreateClientDto } from './dto/create-client.dto';
import {
  TokenDto,
  LoginResponseDto,
  ClientCreateResponseDto,
} from './dto/response.dto';
import { JwtAuthGuard } from './jwt-auth.guard';
import { PermissionsGuard, RequirePermissions } from './permissions.guard';
import { User } from './user.entity';
import type { AuthenticatedRequest } from '../types/auth.types';
import {
  PERMISSIONS,
  TOKEN_TYPES,
  type TokenType,
} from '../constants/auth.constants';
import { ConfigService } from '@nestjs/config';

import { ValidationHelpers } from './validation.helpers';

@Controller('auth')
@UseGuards(ThrottlerGuard)
@ApiTags('Authentication')
export class AuthController {
  constructor(
    private readonly configService: ConfigService,
    private readonly authService: AuthService,
  ) {}

  @Post('register')
  @ApiOperation({ summary: '사용자 등록' })
  @ApiResponse({
    status: 201,
    description: '사용자가 성공적으로 등록됨',
  })
  @ApiResponse({
    status: 400,
    description: '잘못된 요청 데이터',
  })
  @ApiBody({ type: CreateUserDto })
  async register(@Body() createUserDto: CreateUserDto): Promise<User> {
    const user = await this.authService.register(createUserDto);
    return user;
  }

  @Post('login')
  @Throttle({ default: { limit: 5, ttl: 60000 } }) // 1분에 5번 로그인 시도 제한
  @ApiOperation({ summary: '사용자 로그인' })
  @ApiResponse({
    status: 200,
    description: '로그인 성공',
    type: LoginResponseDto,
  })
  @ApiResponse({
    status: 401,
    description: '인증 실패',
  })
  @ApiBody({ type: LoginDto })
  async login(
    @Body() loginDto: LoginDto,
    @Res({ passthrough: true }) res: Response,
  ): Promise<LoginResponseDto> {
    const result = await this.authService.login(loginDto);

    // OAuth2 플로우를 위해 쿠키에 토큰 설정
    res.cookie('token', result.accessToken, {
      httpOnly: false,
      secure: this.configService.get('NODE_ENV') === 'production',
      sameSite: 'lax',
      maxAge: 24 * 60 * 60 * 1000, // 24h
    });

    return result;
  }

  @Post('verify-2fa')
  @ApiOperation({ summary: '2FA 토큰 검증 및 로그인 완료' })
  @ApiResponse({
    status: 200,
    description: '2FA 검증 성공 및 로그인 완료',
    type: LoginResponseDto,
  })
  @ApiResponse({
    status: 401,
    description: '잘못된 2FA 토큰',
  })
  @ApiBody({
    schema: {
      type: 'object',
      properties: {
        email: { type: 'string', format: 'email' },
        token: { type: 'string', minLength: 6, maxLength: 6 },
      },
      required: ['email', 'token'],
    },
  })
  async verifyTwoFactorLogin(
    @Body() body: { email: string; token: string },
    @Res({ passthrough: true }) res: Response,
  ): Promise<LoginResponseDto> {
    const { email, token } = body;

    // 입력 검증 강화
    if (!email || typeof email !== 'string') {
      throw new BadRequestException('이메일이 필요합니다.');
    }
    if (!token || typeof token !== 'string') {
      throw new BadRequestException('2FA 토큰이 필요합니다.');
    }

    // 이메일 형식 검증
    ValidationHelpers.validateEmail(email.trim());

    // 2FA 토큰 형식 검증
    ValidationHelpers.validateTwoFactorToken(token.trim());

    const result = await this.authService.verifyTwoFactorToken(
      email.trim(),
      token.trim(),
    );

    // OAuth2 플로우를 위해 쿠키에 토큰 설정
    res.cookie('token', result.accessToken, {
      httpOnly: false,
      secure: this.configService.get('NODE_ENV') === 'production',
      sameSite: 'lax',
      maxAge: 24 * 60 * 60 * 1000, // 24h
    });

    return result;
  }

  @Post('logout')
  @UseGuards(JwtAuthGuard)
  @ApiBearerAuth()
  @ApiOperation({ summary: '사용자 로그아웃' })
  @ApiResponse({
    status: 200,
    description: '로그아웃 성공',
  })
  @ApiResponse({
    status: 401,
    description: '인증되지 않은 요청',
  })
  async logout(
    @Request() req: ExpressRequest,
    @Res({ passthrough: true }) res: Response,
  ) {
    const token = ValidationHelpers.extractBearerToken(req);
    const result = await this.authService.logout(token);

    // 쿠키 제거
    res.clearCookie('token', {
      httpOnly: false,
      secure: this.configService.get('NODE_ENV') === 'production',
      sameSite: 'lax',
    });

    return result;
  }

  @Post('refresh')
  @UseGuards(JwtAuthGuard)
  @ApiBearerAuth()
  @ApiOperation({ summary: 'JWT 토큰 리프래시' })
  @ApiResponse({
    status: 200,
    description: '토큰 리프래시 성공',
    type: LoginResponseDto,
  })
  @ApiResponse({
    status: 401,
    description: '유효하지 않은 토큰',
  })
  refresh(@Request() req: ExpressRequest) {
    const token = ValidationHelpers.extractBearerToken(req);
    return this.authService.refreshToken(token);
  }

  @Post('verify-backup-code')
  @ApiOperation({ summary: '백업 코드 검증 및 로그인 완료' })
  @ApiResponse({
    status: 200,
    description: '백업 코드 검증 성공 및 로그인 완료',
    type: LoginResponseDto,
  })
  @ApiResponse({
    status: 401,
    description: '잘못된 백업 코드',
  })
  @ApiBody({
    schema: {
      type: 'object',
      properties: {
        email: { type: 'string', format: 'email' },
        backupCode: { type: 'string', minLength: 8, maxLength: 14 },
      },
      required: ['email', 'backupCode'],
    },
  })
  async verifyBackupCodeLogin(
    @Body() body: { email: string; backupCode: string },
    @Res({ passthrough: true }) res: Response,
  ): Promise<LoginResponseDto> {
    const { email, backupCode } = body;

    // 입력 검증 강화
    if (!email || typeof email !== 'string') {
      throw new BadRequestException('이메일이 필요합니다.');
    }
    if (!backupCode || typeof backupCode !== 'string') {
      throw new BadRequestException('백업 코드가 필요합니다.');
    }

    // 이메일 형식 검증
    ValidationHelpers.validateEmail(email.trim());

    // 백업 코드 형식 검증
    ValidationHelpers.validateBackupCode(backupCode.trim());

    const result = await this.authService.verifyBackupCode(
      email.trim(),
      backupCode.trim(),
    );

    // OAuth2 플로우를 위해 쿠키에 토큰 설정
    res.cookie('token', result.accessToken, {
      httpOnly: false,
      secure: this.configService.get('NODE_ENV') === 'production',
      sameSite: 'lax',
      maxAge: 24 * 60 * 60 * 1000, // 24h
    });

    return result;
  }

  @Post('clients')
  @UseGuards(JwtAuthGuard, PermissionsGuard)
  @RequirePermissions(PERMISSIONS.WRITE_CLIENT)
  @ApiBearerAuth()
  @ApiTags('Client Management')
  @ApiOperation({
    summary: 'OAuth2 클라이언트 생성',
    description: `
새로운 OAuth2 클라이언트 애플리케이션을 등록합니다.

**필요 권한:** write:client
    `,
  })
  @ApiResponse({
    status: 201,
    description: '클라이언트가 성공적으로 생성됨',
    type: ClientCreateResponseDto,
  })
  @ApiResponse({
    status: 400,
    description: '잘못된 요청 데이터',
  })
  @ApiResponse({
    status: 403,
    description: '권한이 없음',
  })
  @ApiBody({ type: CreateClientDto })
  async createClient(
    @Body() createClientDto: CreateClientDto,
    @Request() req: AuthenticatedRequest,
  ): Promise<ClientCreateResponseDto> {
    const client = await this.authService.createClient(
      createClientDto,
      req.user.id,
    );
    return {
      id: client.id,
      clientId: client.clientId,
      clientSecret: client.clientSecret || undefined,
      name: client.name,
      description: client.description,
      createdAt: client.createdAt,
    };
  }

  @Get('clients')
  @UseGuards(JwtAuthGuard, PermissionsGuard)
  @RequirePermissions(PERMISSIONS.READ_CLIENT)
  @ApiBearerAuth()
  @ApiTags('Client Management')
  @ApiOperation({
    summary: '사용자의 OAuth2 클라이언트 목록 조회',
    description: `
현재 사용자가 소유한 모든 OAuth2 클라이언트를 조회합니다.

**필요 권한:** read:client
    `,
  })
  @ApiResponse({
    status: 200,
    description: '클라이언트 목록 반환',
  })
  @ApiResponse({
    status: 403,
    description: '권한이 없음',
  })
  async getClients(@Request() req: any) {
    ValidationHelpers.validateAuthenticatedRequest(req);
    const clients = await this.authService.getClients(req.user.id);
    return clients.map((client) => ({
      id: client.id,
      clientId: client.clientId,
      name: client.name,
      description: client.description,
      redirectUris: client.redirectUris,
      grants: client.grants,
      scopes: client.scopes,
      logoUri: client.logoUri,
      termsOfServiceUri: client.termsOfServiceUri,
      policyUri: client.policyUri,
      isActive: client.isActive,
      createdAt: client.createdAt,
      updatedAt: client.updatedAt,
    }));
  }

  @Get('clients/:id')
  @UseGuards(JwtAuthGuard, PermissionsGuard)
  @RequirePermissions(PERMISSIONS.READ_CLIENT)
  @ApiBearerAuth()
  @ApiOperation({ summary: '특정 OAuth2 클라이언트 조회' })
  @ApiResponse({
    status: 200,
    description: '클라이언트 정보 반환',
  })
  @ApiResponse({
    status: 404,
    description: '클라이언트를 찾을 수 없음',
  })
  @ApiResponse({
    status: 403,
    description: '권한이 없음',
  })
  async getClientById(
    @Param('id') id: string,
    @Request() req: AuthenticatedRequest,
  ) {
    const client = await this.authService.getClientById(
      ValidationHelpers.parseIdParam(id),
      req.user.id,
    );
    return {
      id: client.id,
      clientId: client.clientId,
      name: client.name,
      description: client.description,
      redirectUris: client.redirectUris,
      grants: client.grants,
      scopes: client.scopes,
      logoUri: client.logoUri,
      termsOfServiceUri: client.termsOfServiceUri,
      policyUri: client.policyUri,
      isActive: client.isActive,
      createdAt: client.createdAt,
      updatedAt: client.updatedAt,
    };
  }

  @Patch('clients/:id/status')
  @UseGuards(JwtAuthGuard, PermissionsGuard)
  @RequirePermissions(PERMISSIONS.WRITE_CLIENT)
  @ApiBearerAuth()
  @ApiOperation({ summary: 'OAuth2 클라이언트 상태 업데이트' })
  @ApiResponse({
    status: 200,
    description: '클라이언트 상태가 성공적으로 업데이트됨',
  })
  @ApiResponse({
    status: 404,
    description: '클라이언트를 찾을 수 없음',
  })
  @ApiResponse({
    status: 403,
    description: '권한이 없음',
  })
  @ApiBody({
    schema: {
      type: 'object',
      properties: {
        isActive: { type: 'boolean', example: true },
      },
    },
  })
  async updateClientStatus(
    @Param('id') id: string,
    @Body() body: { isActive: boolean },
    @Request() req: AuthenticatedRequest,
  ) {
    return this.authService.updateClientStatus(
      ValidationHelpers.parseIdParam(id),
      body.isActive,
      req.user.id,
    );
  }

  @Patch('clients/:id')
  @UseGuards(JwtAuthGuard, PermissionsGuard)
  @RequirePermissions(PERMISSIONS.WRITE_CLIENT)
  @ApiBearerAuth()
  @ApiOperation({ summary: 'OAuth2 클라이언트 정보 업데이트' })
  @ApiResponse({
    status: 200,
    description: '클라이언트 정보가 성공적으로 업데이트됨',
  })
  @ApiResponse({
    status: 404,
    description: '클라이언트를 찾을 수 없음',
  })
  @ApiResponse({
    status: 403,
    description: '권한이 없음',
  })
  @ApiBody({
    schema: {
      type: 'object',
      properties: {
        name: { type: 'string', example: 'My App' },
        description: { type: 'string', example: 'My awesome application' },
        redirectUris: {
          type: 'array',
          items: { type: 'string' },
          example: ['https://example.com/callback'],
        },
        scopes: {
          type: 'array',
          items: { type: 'string' },
          example: ['identify', 'email'],
        },
      },
    },
  })
  async updateClient(
    @Param('id') id: string,
    @Body() updateData: Partial<CreateClientDto>,
    @Request() req: AuthenticatedRequest,
  ) {
    // 요청 본문 검증 강화
    if (!updateData || typeof updateData !== 'object') {
      throw new BadRequestException('업데이트 데이터가 필요합니다.');
    }

    // redirectUris 검증
    if (updateData.redirectUris !== undefined) {
      if (!Array.isArray(updateData.redirectUris)) {
        throw new BadRequestException('redirectUris는 배열이어야 합니다.');
      }
      for (const uri of updateData.redirectUris) {
        if (typeof uri !== 'string' || !uri.trim()) {
          throw new BadRequestException(
            'redirectUris의 각 항목은 비어있지 않은 문자열이어야 합니다.',
          );
        }
        // 간단한 URL 형식 검증
        try {
          new URL(uri.trim());
        } catch {
          throw new BadRequestException(`잘못된 URL 형식: ${uri}`);
        }
      }
    }

    // scopes 검증
    if (updateData.scopes !== undefined) {
      if (!Array.isArray(updateData.scopes)) {
        throw new BadRequestException('scopes는 배열이어야 합니다.');
      }
      for (const scope of updateData.scopes) {
        if (typeof scope !== 'string' || !scope.trim()) {
          throw new BadRequestException(
            'scopes의 각 항목은 비어있지 않은 문자열이어야 합니다.',
          );
        }
      }
    }

    // name 검증
    if (updateData.name !== undefined) {
      if (typeof updateData.name !== 'string' || !updateData.name.trim()) {
        throw new BadRequestException(
          'name은 비어있지 않은 문자열이어야 합니다.',
        );
      }
    }

    return this.authService.updateClient(
      ValidationHelpers.parseIdParam(id),
      updateData,
      req.user.id,
    );
  }

  @Put('clients/:id/reset-secret')
  @UseGuards(JwtAuthGuard, PermissionsGuard)
  @RequirePermissions(PERMISSIONS.WRITE_CLIENT)
  @ApiBearerAuth()
  @ApiOperation({ summary: 'OAuth2 클라이언트 시크릿 재설정' })
  @ApiResponse({
    status: 200,
    description: '클라이언트 시크릿이 성공적으로 재설정됨',
    schema: {
      type: 'object',
      properties: {
        id: { type: 'number' },
        clientId: { type: 'string' },
        clientSecret: { type: 'string' },
        name: { type: 'string' },
        description: { type: 'string' },
        redirectUris: { type: 'array', items: { type: 'string' } },
        grants: { type: 'array', items: { type: 'string' } },
        scopes: { type: 'array', items: { type: 'string' } },
        logoUri: { type: 'string', nullable: true },
        termsOfServiceUri: { type: 'string' },
        policyUri: { type: 'string' },
        isActive: { type: 'boolean' },
        createdAt: { type: 'string', format: 'date-time' },
        updatedAt: { type: 'string', format: 'date-time' },
      },
    },
  })
  @ApiResponse({
    status: 404,
    description: '클라이언트를 찾을 수 없음',
  })
  @ApiResponse({
    status: 403,
    description: '권한이 없음',
  })
  async resetClientSecret(
    @Param('id') id: string,
    @Request() req: AuthenticatedRequest,
  ) {
    const client = await this.authService.resetClientSecret(
      ValidationHelpers.parseIdParam(id),
      req.user.id,
    );
    return {
      id: client.id,
      clientId: client.clientId,
      clientSecret: client.clientSecret,
      name: client.name,
      description: client.description,
      redirectUris: client.redirectUris,
      grants: client.grants,
      scopes: client.scopes,
      logoUri: client.logoUri,
      termsOfServiceUri: client.termsOfServiceUri,
      policyUri: client.policyUri,
      isActive: client.isActive,
      createdAt: client.createdAt,
      updatedAt: client.updatedAt,
    };
  }

  @Delete('clients/:id/logo')
  @UseGuards(JwtAuthGuard, PermissionsGuard)
  @RequirePermissions(PERMISSIONS.WRITE_CLIENT)
  @ApiBearerAuth()
  @ApiOperation({ summary: 'OAuth2 클라이언트 로고 제거' })
  @ApiResponse({
    status: 200,
    description: '클라이언트 로고가 성공적으로 제거됨',
    schema: {
      type: 'object',
      properties: {
        id: { type: 'number' },
        clientId: { type: 'string' },
        name: { type: 'string' },
        description: { type: 'string' },
        logoUri: { type: 'string', nullable: true },
        termsOfServiceUri: { type: 'string' },
        policyUri: { type: 'string' },
        isActive: { type: 'boolean' },
        createdAt: { type: 'string', format: 'date-time' },
        updatedAt: { type: 'string', format: 'date-time' },
      },
    },
  })
  @ApiResponse({
    status: 404,
    description: '클라이언트를 찾을 수 없음',
  })
  @ApiResponse({
    status: 403,
    description: '권한이 없음',
  })
  async removeClientLogo(
    @Param('id') id: string,
    @Request() req: AuthenticatedRequest,
  ) {
    return this.authService.removeClientLogo(
      ValidationHelpers.parseIdParam(id),
      req.user.id,
    );
  }

  @Delete('clients/:id')
  @UseGuards(JwtAuthGuard, PermissionsGuard)
  @RequirePermissions(PERMISSIONS.DELETE_CLIENT)
  @ApiBearerAuth()
  @ApiOperation({ summary: 'OAuth2 클라이언트 삭제' })
  @ApiResponse({
    status: 200,
    description: '클라이언트가 성공적으로 삭제됨',
  })
  @ApiResponse({
    status: 404,
    description: '클라이언트를 찾을 수 없음',
  })
  @ApiResponse({
    status: 403,
    description: '권한이 없음',
  })
  async deleteClient(@Param('id') id: string) {
    await this.authService.deleteClient(ValidationHelpers.parseIdParam(id));
    return { message: 'Client deleted successfully' };
  }

  @Get('tokens')
  @UseGuards(JwtAuthGuard, PermissionsGuard)
  @RequirePermissions(PERMISSIONS.READ_TOKEN)
  @ApiBearerAuth()
  @ApiOperation({ summary: '사용자 토큰 목록 조회' })
  @ApiResponse({
    status: 200,
    description: '토큰 목록 반환',
    type: [TokenDto],
  })
  async getUserTokens(@Request() req: AuthenticatedRequest) {
    return this.authService.getUserTokens(req.user.id);
  }

  @Delete('tokens/:id')
  @UseGuards(JwtAuthGuard, PermissionsGuard)
  @RequirePermissions(PERMISSIONS.DELETE_TOKEN)
  @ApiBearerAuth()
  @ApiOperation({ summary: '특정 토큰 취소' })
  @ApiResponse({
    status: 200,
    description: '토큰이 성공적으로 취소됨',
  })
  @ApiResponse({
    status: 404,
    description: '토큰을 찾을 수 없음',
  })
  @ApiResponse({
    status: 403,
    description: '권한이 없음',
  })
  async revokeToken(
    @Request() req: AuthenticatedRequest,
    @Param('id') tokenId: string,
  ) {
    await this.authService.revokeToken(
      req.user.id,
      ValidationHelpers.parseIdParam(tokenId),
    );
    return { message: 'Token revoked successfully' };
  }

  @Delete('tokens')
  @UseGuards(JwtAuthGuard, PermissionsGuard)
  @RequirePermissions(PERMISSIONS.DELETE_TOKEN)
  @ApiBearerAuth()
  @ApiOperation({ summary: '모든 사용자 토큰 취소' })
  @ApiResponse({
    status: 200,
    description: '모든 토큰이 성공적으로 취소됨',
  })
  @ApiResponse({
    status: 403,
    description: '권한이 없음',
  })
  async revokeAllUserTokens(@Request() req: AuthenticatedRequest) {
    await this.authService.revokeAllUserTokens(req.user.id);
    return { message: 'All user tokens revoked successfully' };
  }

  @Delete('tokens/type/:tokenType')
  @UseGuards(JwtAuthGuard, PermissionsGuard)
  @RequirePermissions(PERMISSIONS.DELETE_TOKEN)
  @ApiBearerAuth()
  @ApiOperation({ summary: '특정 타입의 모든 토큰 취소' })
  @ApiResponse({
    status: 200,
    description: '토큰 타입별 토큰들이 성공적으로 취소됨',
  })
  @ApiResponse({
    status: 400,
    description: '잘못된 토큰 타입',
  })
  @ApiResponse({
    status: 403,
    description: '권한이 없음',
  })
  async revokeAllTokensForType(
    @Request() req: AuthenticatedRequest,
    @Param('tokenType') tokenType: string,
  ) {
    // 토큰 타입 검증 강화
    if (!tokenType || typeof tokenType !== 'string') {
      throw new BadRequestException('토큰 타입이 필요합니다.');
    }

    const trimmedTokenType = tokenType.trim();
    if (!trimmedTokenType) {
      throw new BadRequestException('토큰 타입이 비어있을 수 없습니다.');
    }

    // 허용된 토큰 타입인지 검증
    if (!Object.values(TOKEN_TYPES).includes(trimmedTokenType as TokenType)) {
      throw new BadRequestException('잘못된 토큰 타입입니다.');
    }

    await this.authService.revokeAllTokensForType(
      req.user.id,
      trimmedTokenType as TokenType,
    );
    return { message: `${trimmedTokenType} tokens revoked successfully` };
  }
}
