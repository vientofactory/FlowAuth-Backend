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
} from '@nestjs/common';
import {
  ApiTags,
  ApiOperation,
  ApiResponse,
  ApiBody,
  ApiBearerAuth,
} from '@nestjs/swagger';
import type { Response } from 'express';
import { AuthService } from './auth.service';
import { CreateUserDto } from './dto/create-user.dto';
import { LoginDto } from './dto/login.dto';
import { CreateClientDto } from './dto/create-client.dto';
import { JwtAuthGuard } from './jwt-auth.guard';
import { PermissionsGuard, RequirePermissions } from './permissions.guard';
import { User } from '../user/user.entity';
import type { AuthenticatedRequest } from '../types/auth.types';
import { PERMISSIONS } from '../constants/auth.constants';
import { LoginResponseDto, ClientCreateResponseDto } from './dto/response.dto';

@Controller('auth')
@ApiTags('Authentication')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

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
      httpOnly: false, // JavaScript에서 접근 가능하도록 설정
      secure: false, // 개발 환경에서는 false, 프로덕션에서는 true
      sameSite: 'lax',
      maxAge: 24 * 60 * 60 * 1000, // 24시간
    });

    return result;
  }

  @Get('profile')
  @UseGuards(JwtAuthGuard)
  @ApiBearerAuth()
  @ApiOperation({ summary: '사용자 프로필 조회' })
  @ApiResponse({
    status: 200,
    description: '프로필 정보 반환',
  })
  @ApiResponse({
    status: 401,
    description: '인증되지 않은 사용자',
  })
  async getProfile(@Request() req: AuthenticatedRequest) {
    const user = await this.authService.findById(req.user.id);
    return user;
  }

  @Put('profile')
  @UseGuards(JwtAuthGuard)
  @ApiBearerAuth()
  @ApiOperation({ summary: '사용자 프로필 업데이트' })
  @ApiResponse({
    status: 200,
    description: '프로필 업데이트 성공',
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
  ) {
    const userId = req.user.id;
    return this.authService.updateProfile(userId, updateData);
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
  async getClients(@Request() req: AuthenticatedRequest) {
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
      parseInt(id),
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
      parseInt(id),
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
          example: ['read', 'write'],
        },
      },
    },
  })
  async updateClient(
    @Param('id') id: string,
    @Body() updateData: Partial<CreateClientDto>,
    @Request() req: AuthenticatedRequest,
  ) {
    return this.authService.updateClient(parseInt(id), updateData, req.user.id);
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
      parseInt(id),
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
    return this.authService.removeClientLogo(parseInt(id), req.user.id);
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
    await this.authService.deleteClient(parseInt(id));
    return { message: 'Client deleted successfully' };
  }

  @Get('tokens')
  @UseGuards(JwtAuthGuard)
  @ApiBearerAuth()
  @ApiOperation({ summary: '사용자 토큰 목록 조회' })
  @ApiResponse({
    status: 200,
    description: '토큰 목록 반환',
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
    await this.authService.revokeToken(req.user.id, parseInt(tokenId));
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
}
