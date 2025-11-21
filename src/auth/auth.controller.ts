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
  ApiParam,
  ApiBearerAuth,
} from '@nestjs/swagger';
import { ThrottlerGuard } from '@nestjs/throttler';
import type { Response, Request as ExpressRequest } from 'express';
import { AuthService } from './auth.service';
import { CreateUserDto } from './dto/create-user.dto';
import { LoginDto } from './dto/login.dto';
import { CreateClientDto } from './dto/create-client.dto';
import {
  RequestPasswordResetDto,
  ResetPasswordDto,
} from './dto/password-reset.dto';
import {
  TokenDto,
  LoginResponseDto,
  ClientCreateResponseDto,
  AvailabilityResponseDto,
} from './dto/response.dto';
import { JwtAuthGuard } from './jwt-auth.guard';
import { PermissionsGuard, RequirePermissions } from './permissions.guard';
import { User } from './user.entity';
import type { AuthenticatedRequest } from '../types/auth.types';
import { PERMISSIONS, TOKEN_TYPES, type TokenType } from '@flowauth/shared';
import { ConfigService } from '@nestjs/config';
import { TokenAuthService } from './services/token-auth.service';
import { ValidationService } from './services/validation.service';
import { validateOAuth2RedirectUri } from '../utils/url-security.util';
import { RequestInfoUtils } from '../utils/request-info.util';
import {
  AdvancedRateLimitGuard,
  RateLimit,
} from '../common/guards/advanced-rate-limit.guard';
import { PasswordResetRateLimitGuard } from '../common/guards/password-reset-rate-limit.guard';
import {
  DefaultFieldSizeLimitPipe,
  RecaptchaFieldSizeLimitPipe,
} from '../common/middleware/size-limit.middleware';
import {
  RATE_LIMIT_CONFIGS,
  KEY_GENERATORS,
} from '../constants/security.constants';

@Controller('auth')
@UseGuards(ThrottlerGuard, AdvancedRateLimitGuard)
@ApiTags('Authentication')
export class AuthController {
  constructor(
    private readonly configService: ConfigService,
    private readonly authService: AuthService,
    private readonly tokenAuthService: TokenAuthService,
  ) {}

  @Post('register')
  @RateLimit(RATE_LIMIT_CONFIGS.AUTH_REGISTER)
  @ApiOperation({ summary: '사용자 등록 (보안 강화)' })
  @ApiResponse({
    status: 201,
    description: '사용자가 성공적으로 등록됨',
  })
  @ApiResponse({
    status: 400,
    description: '잘못된 요청 데이터',
  })
  @ApiResponse({
    status: 429,
    description: '요청 제한 초과 (1시간에 3회)',
  })
  @ApiBody({ type: CreateUserDto })
  async register(@Body() createUserDto: CreateUserDto): Promise<User> {
    const user = await this.authService.register(createUserDto);
    return user;
  }

  @Get('check-email/:email')
  @ApiOperation({ summary: '이메일 가용성 확인' })
  @ApiParam({
    name: 'email',
    description: '확인할 이메일 주소',
    example: 'user@example.com',
  })
  @ApiResponse({
    status: 200,
    description: '이메일 가용성 확인 결과',
    type: AvailabilityResponseDto,
  })
  async checkEmail(
    @Param('email') email: string,
  ): Promise<AvailabilityResponseDto> {
    const result = await this.authService.checkEmailAvailability(email);
    return result;
  }

  @Get('check-username/:username')
  @ApiOperation({ summary: '사용자명 가용성 확인' })
  @ApiParam({
    name: 'username',
    description: '확인할 사용자명',
    example: 'johndoe',
  })
  @ApiResponse({
    status: 200,
    description: '사용자명 가용성 확인 결과',
    type: AvailabilityResponseDto,
  })
  async checkUsername(
    @Param('username') username: string,
  ): Promise<AvailabilityResponseDto> {
    const result = await this.authService.checkUsernameAvailability(username);
    return result;
  }

  @Post('login')
  @RateLimit({
    ...RATE_LIMIT_CONFIGS.AUTH_LOGIN,
    keyGenerator: KEY_GENERATORS.IP_USER_AGENT,
  })
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
  @ApiResponse({
    status: 429,
    description: '로그인 시도 제한 초과 (15분에 5회, 봇 탐지)',
  })
  @ApiBody({ type: LoginDto })
  async login(
    @Body(RecaptchaFieldSizeLimitPipe)
    loginDto: LoginDto,
    @Res({ passthrough: true }) res: Response,
    @Request() req: ExpressRequest,
  ): Promise<LoginResponseDto> {
    // Extract client information
    const clientInfo = RequestInfoUtils.getClientInfo(req);

    const result = await this.authService.login(loginDto, clientInfo);

    res.cookie('token', result.accessToken, {
      httpOnly: true,
      secure: this.configService.get('NODE_ENV') === 'production',
      sameSite: 'strict',
      maxAge: 24 * 60 * 60 * 1000, // 24h
    });

    return result;
  }

  @Post('verify-2fa')
  @RateLimit(RATE_LIMIT_CONFIGS.AUTH_2FA_VERIFY)
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
    @Body(DefaultFieldSizeLimitPipe) body: { email: string; token: string },
    @Res({ passthrough: true }) res: Response,
  ): Promise<LoginResponseDto> {
    const { email, token } = body;

    // Enhanced input validation
    if (!email || typeof email !== 'string') {
      throw new BadRequestException('이메일이 필요합니다.');
    }
    if (!token || typeof token !== 'string') {
      throw new BadRequestException('2FA 토큰이 필요합니다.');
    }

    // Email format validation
    ValidationService.validateEmail(email.trim());

    // 2FA token format validation
    ValidationService.validateTwoFactorToken(token.trim());

    const result = await this.authService.verifyTwoFactorToken(
      email.trim(),
      token.trim(),
    );

    res.cookie('token', result.accessToken, {
      httpOnly: true,
      secure: this.configService.get('NODE_ENV') === 'production',
      sameSite: 'strict',
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
  logout(
    @Request() req: ExpressRequest,
    @Res({ passthrough: true }) res: Response,
  ) {
    const token = ValidationService.extractBearerToken(req);
    const result = this.authService.logout(token);

    res.clearCookie('token', {
      httpOnly: true,
      secure: this.configService.get('NODE_ENV') === 'production',
      sameSite: 'strict',
    });

    return result;
  }

  @Post('refresh')
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
  @ApiBody({
    schema: {
      type: 'object',
      properties: {
        refreshToken: { type: 'string', description: '리프래시 토큰' },
      },
      required: ['refreshToken'],
    },
  })
  refresh(@Body() body: { refreshToken: string }) {
    return this.tokenAuthService.refreshToken(body.refreshToken);
  }

  @Post('verify-backup-code')
  @RateLimit(RATE_LIMIT_CONFIGS.AUTH_BACKUP_CODE)
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
    @Body(DefaultFieldSizeLimitPipe)
    body: { email: string; backupCode: string },
    @Res({ passthrough: true }) res: Response,
  ): Promise<LoginResponseDto> {
    const { email, backupCode } = body;

    // Enhanced input validation
    if (!email || typeof email !== 'string') {
      throw new BadRequestException('이메일이 필요합니다.');
    }
    if (!backupCode || typeof backupCode !== 'string') {
      throw new BadRequestException('백업 코드가 필요합니다.');
    }

    // Email format validation
    ValidationService.validateEmail(email.trim());

    // Backup code format validation
    ValidationService.validateBackupCode(backupCode.trim());

    const result = await this.authService.verifyBackupCode(
      email.trim(),
      backupCode.trim(),
    );

    res.cookie('token', result.accessToken, {
      httpOnly: true,
      secure: this.configService.get('NODE_ENV') === 'production',
      sameSite: 'strict',
      maxAge: 24 * 60 * 60 * 1000, // 24h
    });

    return result;
  }

  @Post('clients')
  @UseGuards(JwtAuthGuard, PermissionsGuard)
  @RequirePermissions(PERMISSIONS.WRITE_CLIENT)
  @ApiBearerAuth()
  @ApiTags('OAuth2 Management')
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
    @Body(RecaptchaFieldSizeLimitPipe) createClientDto: CreateClientDto,
    @Request() req: AuthenticatedRequest,
  ): Promise<ClientCreateResponseDto> {
    const client = await this.authService.createClient(
      createClientDto,
      req.user.id,
    );
    return {
      id: client.id,
      clientId: client.clientId,
      clientSecret: client.clientSecret ?? undefined,
      name: client.name,
      description: client.description,
      createdAt: client.createdAt,
    };
  }

  @Get('clients')
  @UseGuards(JwtAuthGuard, PermissionsGuard)
  @RequirePermissions(PERMISSIONS.READ_CLIENT)
  @ApiBearerAuth()
  @ApiTags('OAuth2 Management')
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
    ValidationService.validateAuthenticatedRequest(req);
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
      ValidationService.validateIdParam(id),
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
  @ApiOperation({
    summary: 'OAuth2 클라이언트 상태 업데이트 (소유자 또는 관리자)',
    description: `
클라이언트의 활성화 상태를 변경합니다.

**권한 모델:**
- 자신이 생성한 클라이언트만 상태 변경 가능
- 관리자는 모든 클라이언트 상태 변경 가능

**필요 권한:** write:client
    `,
  })
  @ApiResponse({
    status: 200,
    description: '클라이언트 상태가 성공적으로 업데이트됨',
  })
  @ApiResponse({
    status: 404,
    description: '클라이언트를 찾을 수 없음 또는 소유권이 없음',
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
      ValidationService.validateIdParam(id),
      body.isActive,
      req.user.id,
    );
  }

  @Patch('clients/:id')
  @UseGuards(JwtAuthGuard, PermissionsGuard)
  @RequirePermissions(PERMISSIONS.WRITE_CLIENT)
  @ApiBearerAuth()
  @ApiOperation({
    summary: 'OAuth2 클라이언트 정보 업데이트 (소유자 또는 관리자)',
    description: `
클라이언트의 기본 정보를 업데이트합니다.

**권한 모델:**
- 자신이 생성한 클라이언트만 정보 수정 가능
- 관리자는 모든 클라이언트 정보 수정 가능

**업데이트 가능 필드:**
- name: 클라이언트 이름
- description: 클라이언트 설명
- redirectUris: 리다이렉트 URI 목록
- scopes: 사용 가능한 스코프 목록

**필요 권한:** write:client
    `,
  })
  @ApiResponse({
    status: 200,
    description: '클라이언트 정보가 성공적으로 업데이트됨',
  })
  @ApiResponse({
    status: 404,
    description: '클라이언트를 찾을 수 없음 또는 소유권이 없음',
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
    // Enhanced request body validation
    if (!updateData || typeof updateData !== 'object') {
      throw new BadRequestException('업데이트 데이터가 필요합니다.');
    }

    // Validate redirectUris
    if (updateData.redirectUris !== undefined) {
      for (const uri of updateData.redirectUris) {
        if (!validateOAuth2RedirectUri(uri)) {
          throw new BadRequestException(`Invalid redirect URI: ${uri}`);
        }
      }
    }

    // Validate scopes
    if (updateData.scopes !== undefined) {
      ValidationService.validateStringArray(updateData.scopes, 'scopes');
    }

    // Validate name
    if (updateData.name !== undefined) {
      ValidationService.validateRequiredString(updateData.name, 'name');
    }

    return this.authService.updateClient(
      ValidationService.validateIdParam(id),
      updateData,
      req.user.id,
    );
  }

  @Put('clients/:id/reset-secret')
  @RateLimit(RATE_LIMIT_CONFIGS.AUTH_PASSWORD_RESET)
  @UseGuards(JwtAuthGuard, PermissionsGuard)
  @RequirePermissions(PERMISSIONS.WRITE_CLIENT)
  @ApiBearerAuth()
  @ApiOperation({
    summary: 'OAuth2 클라이언트 시크릿 재설정 (소유자 또는 관리자)',
    description: `
클라이언트의 시크릿 키를 새로 생성합니다.

**보안 주의사항:**
- 기존 시크릿은 즉시 무효화됩니다
- 새 시크릿을 안전한 곳에 저장하세요
- 이 작업은 되돌릴 수 없습니다

**권한 모델:**
- 자신이 생성한 클라이언트만 시크릿 재설정 가능
- 관리자는 모든 클라이언트 시크릿 재설정 가능

**필요 권한:** write:client
    `,
  })
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
    description: '클라이언트를 찾을 수 없음 또는 소유권이 없음',
  })
  @ApiResponse({
    status: 403,
    description: '권한이 없음',
  })
  @ApiResponse({
    status: 429,
    description: '요청 제한 초과 (보안 작업)',
  })
  async resetClientSecret(
    @Param('id') id: string,
    @Request() req: AuthenticatedRequest,
  ) {
    const client = await this.authService.resetClientSecret(
      ValidationService.validateIdParam(id),
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
      ValidationService.validateIdParam(id),
      req.user.id,
    );
  }

  @Delete('clients/:id')
  @UseGuards(JwtAuthGuard, PermissionsGuard)
  @RequirePermissions(PERMISSIONS.DELETE_CLIENT)
  @ApiBearerAuth()
  @ApiOperation({
    summary: 'OAuth2 클라이언트 삭제 (관리자 권한)',
    description: `
OAuth2 클라이언트를 삭제합니다.

**권한 모델:**
- **관리자 (delete:client 권한)**: 모든 클라이언트 삭제 가능
- **일반 사용자**: /clients/:id/delete-own 엔드포인트 사용 (자신의 클라이언트만)

**필요 권한:** delete:client (관리자 전용)
    `,
  })
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
    description: '관리자 권한이 필요함',
  })
  async deleteClient(
    @Param('id') id: string,
    @Request() req: AuthenticatedRequest,
  ) {
    // Admin can delete all clients
    await this.authService.deleteClient(
      ValidationService.validateIdParam(id),
      req.user.id,
    );
    return { message: 'Client deleted successfully' };
  }

  @Delete('clients/:id/delete-own')
  @UseGuards(JwtAuthGuard, PermissionsGuard)
  @RequirePermissions(PERMISSIONS.WRITE_CLIENT)
  @ApiBearerAuth()
  @ApiOperation({
    summary: '자신의 OAuth2 클라이언트 삭제',
    description: `
현재 사용자가 소유한 OAuth2 클라이언트를 삭제합니다.

**권한 모델:**
- **일반 사용자 (write:client 권한)**: 자신이 생성한 클라이언트만 삭제 가능
- 소유권 검증이 자동으로 수행됩니다

**필요 권한:** write:client
    `,
  })
  @ApiResponse({
    status: 200,
    description: '클라이언트가 성공적으로 삭제됨',
  })
  @ApiResponse({
    status: 404,
    description: '클라이언트를 찾을 수 없음 또는 소유권이 없음',
  })
  @ApiResponse({
    status: 403,
    description: '권한이 없음',
  })
  async deleteOwnClient(
    @Param('id') id: string,
    @Request() req: AuthenticatedRequest,
  ) {
    // Regular users can only delete their own clients
    await this.authService.deleteClient(
      ValidationService.validateIdParam(id),
      req.user.id,
    );
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
      ValidationService.validateIdParam(tokenId),
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
    // Enhanced token type validation
    if (!tokenType || typeof tokenType !== 'string') {
      throw new BadRequestException('토큰 타입이 필요합니다.');
    }

    const trimmedTokenType = tokenType.trim();
    if (!trimmedTokenType) {
      throw new BadRequestException('토큰 타입이 비어있을 수 없습니다.');
    }

    // Validate if token type is allowed
    if (!Object.values(TOKEN_TYPES).includes(trimmedTokenType as TokenType)) {
      throw new BadRequestException('잘못된 토큰 타입입니다.');
    }

    await this.authService.revokeAllTokensForType(
      req.user.id,
      trimmedTokenType as TokenType,
    );
    return { message: `${trimmedTokenType} tokens revoked successfully` };
  }

  @Post('request-password-reset')
  @UseGuards(PasswordResetRateLimitGuard)
  @ApiOperation({ summary: '비밀번호 재설정 요청' })
  @ApiResponse({
    status: 200,
    description: '비밀번호 재설정 이메일이 전송되었습니다.',
    schema: {
      type: 'object',
      properties: {
        message: {
          type: 'string',
          example: '비밀번호 재설정 링크가 이메일로 전송되었습니다.',
        },
      },
    },
  })
  @ApiResponse({
    status: 400,
    description: '잘못된 요청 데이터',
  })
  @ApiResponse({
    status: 429,
    description: '요청 제한 초과',
  })
  @ApiBody({ type: RequestPasswordResetDto })
  async requestPasswordReset(
    @Body(DefaultFieldSizeLimitPipe)
    requestPasswordResetDto: RequestPasswordResetDto,
  ): Promise<{ message: string }> {
    return this.authService.requestPasswordReset(requestPasswordResetDto);
  }

  @Post('reset-password')
  @RateLimit(RATE_LIMIT_CONFIGS.AUTH_PASSWORD_RESET)
  @ApiOperation({ summary: '비밀번호 재설정 실행' })
  @ApiResponse({
    status: 200,
    description: '비밀번호가 성공적으로 변경되었습니다.',
    schema: {
      type: 'object',
      properties: {
        message: {
          type: 'string',
          example: '비밀번호가 성공적으로 변경되었습니다.',
        },
      },
    },
  })
  @ApiResponse({
    status: 400,
    description: '유효하지 않거나 만료된 토큰입니다.',
  })
  @ApiResponse({
    status: 429,
    description: '요청 제한 초과',
  })
  @ApiBody({ type: ResetPasswordDto })
  async resetPassword(
    @Body(DefaultFieldSizeLimitPipe) resetPasswordDto: ResetPasswordDto,
  ): Promise<{ message: string }> {
    return this.authService.resetPassword(resetPasswordDto);
  }

  @Get('validate-reset-token/:token')
  @ApiOperation({ summary: '비밀번호 재설정 토큰 유효성 확인' })
  @ApiParam({
    name: 'token',
    description: '비밀번호 재설정 토큰',
    example: 'abcd1234efgh5678...',
  })
  @ApiResponse({
    status: 200,
    description: '토큰 유효성 확인 결과',
    schema: {
      type: 'object',
      properties: {
        valid: { type: 'boolean', example: true },
        email: {
          type: 'string',
          example: 'user@example.com',
          description: '토큰이 유효한 경우 해당 이메일',
        },
      },
    },
  })
  async validateResetToken(
    @Param('token') token: string,
  ): Promise<{ valid: boolean; email?: string }> {
    return this.authService.validatePasswordResetToken(token);
  }

  @Post('resend-verification')
  @RateLimit(RATE_LIMIT_CONFIGS.AUTH_PASSWORD_RESET)
  @ApiOperation({ summary: '이메일 인증 재전송' })
  @ApiResponse({
    status: 200,
    description: '인증 이메일이 재전송되었습니다.',
    schema: {
      type: 'object',
      properties: {
        message: {
          type: 'string',
          example: '인증 이메일이 전송되었습니다.',
        },
      },
    },
  })
  @ApiResponse({
    status: 400,
    description: '잘못된 요청 데이터 또는 이미 인증된 사용자',
  })
  @ApiResponse({
    status: 429,
    description: '요청 제한 초과',
  })
  @ApiBody({
    schema: {
      type: 'object',
      properties: {
        email: { type: 'string', format: 'email', example: 'user@example.com' },
      },
      required: ['email'],
    },
  })
  async resendVerification(
    @Body(DefaultFieldSizeLimitPipe) body: { email: string },
  ): Promise<{ message: string }> {
    return await this.authService.resendEmailVerification(body.email);
  }

  @Post('verify-email')
  @ApiOperation({ summary: '이메일 인증 확인 (POST)' })
  @ApiResponse({
    status: 200,
    description: '이메일이 성공적으로 인증되었습니다.',
    schema: {
      type: 'object',
      properties: {
        message: {
          type: 'string',
          example: '이메일이 성공적으로 인증되었습니다.',
        },
        email: {
          type: 'string',
          example: 'user@example.com',
          description: '인증된 이메일 주소',
        },
      },
    },
  })
  @ApiResponse({
    status: 400,
    description: '유효하지 않거나 만료된 토큰입니다.',
  })
  @ApiBody({
    schema: {
      type: 'object',
      properties: {
        token: { type: 'string', example: 'abcd1234efgh5678...' },
      },
      required: ['token'],
    },
  })
  async verifyEmail(
    @Body(DefaultFieldSizeLimitPipe) body: { token: string },
  ): Promise<{ message: string; email?: string }> {
    return await this.authService.verifyEmail(body.token);
  }

  @Get('verify-email/:token')
  @ApiOperation({ summary: '이메일 인증 확인 (GET)' })
  @ApiParam({
    name: 'token',
    type: 'string',
    description: '이메일 인증 토큰',
    example: 'abcd1234efgh5678...',
  })
  @ApiResponse({
    status: 200,
    description: '이메일이 성공적으로 인증되었습니다.',
    schema: {
      type: 'object',
      properties: {
        message: {
          type: 'string',
          example: '이메일이 성공적으로 인증되었습니다.',
        },
        email: {
          type: 'string',
          example: 'user@example.com',
          description: '인증된 이메일 주소',
        },
      },
    },
  })
  @ApiResponse({
    status: 400,
    description: '유효하지 않거나 만료된 토큰입니다.',
  })
  async verifyEmailByToken(
    @Param('token') token: string,
  ): Promise<{ message: string; email?: string }> {
    return await this.authService.verifyEmail(token);
  }

  @Get('validate-verification-token/:token')
  @ApiOperation({ summary: '이메일 인증 토큰 유효성 확인' })
  @ApiParam({
    name: 'token',
    description: '이메일 인증 토큰',
    example: 'abcd1234efgh5678...',
  })
  @ApiResponse({
    status: 200,
    description: '토큰 유효성 확인 결과',
    schema: {
      type: 'object',
      properties: {
        valid: { type: 'boolean', example: true },
        email: {
          type: 'string',
          example: 'user@example.com',
          description: '토큰이 유효한 경우 해당 이메일',
        },
      },
    },
  })
  async validateVerificationToken(
    @Param('token') token: string,
  ): Promise<{ valid: boolean; email?: string }> {
    return await this.authService.validateEmailVerificationToken(token);
  }
}
