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
} from '@nestjs/common';
import {
  ApiTags,
  ApiOperation,
  ApiResponse,
  ApiBody,
  ApiBearerAuth,
} from '@nestjs/swagger';
import { AuthService } from './auth.service';
import { CreateUserDto } from './dto/create-user.dto';
import { LoginDto } from './dto/login.dto';
import { CreateClientDto } from './dto/create-client.dto';
import { JwtAuthGuard } from './jwt-auth.guard';
import { User } from '../user/user.entity';
import type { LoginResponse, AuthenticatedRequest } from '../types/auth.types';

@Controller('auth')
@ApiTags('auth')
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
    schema: {
      type: 'object',
      properties: {
        user: {
          type: 'object',
          properties: {
            id: { type: 'number' },
            username: { type: 'string' },
            email: { type: 'string' },
            firstName: { type: 'string' },
            lastName: { type: 'string' },
          },
        },
        accessToken: { type: 'string' },
      },
    },
  })
  @ApiResponse({
    status: 401,
    description: '인증 실패',
  })
  @ApiBody({ type: LoginDto })
  async login(@Body() loginDto: LoginDto): Promise<LoginResponse> {
    const result = await this.authService.login(loginDto);
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
  @ApiOperation({ summary: 'OAuth2 클라이언트 생성' })
  @ApiResponse({
    status: 201,
    description: '클라이언트가 성공적으로 생성됨',
  })
  @ApiResponse({
    status: 400,
    description: '잘못된 요청 데이터',
  })
  @ApiBody({ type: CreateClientDto })
  async createClient(@Body() createClientDto: CreateClientDto) {
    return this.authService.createClient(createClientDto);
  }

  @Get('clients')
  @ApiOperation({ summary: '모든 OAuth2 클라이언트 조회' })
  @ApiResponse({
    status: 200,
    description: '클라이언트 목록 반환',
  })
  async getClients() {
    return this.authService.getClients();
  }

  @Get('clients/:id')
  @ApiOperation({ summary: '특정 OAuth2 클라이언트 조회' })
  @ApiResponse({
    status: 200,
    description: '클라이언트 정보 반환',
  })
  @ApiResponse({
    status: 404,
    description: '클라이언트를 찾을 수 없음',
  })
  async getClientById(@Param('id') id: string) {
    return this.authService.getClientById(parseInt(id));
  }

  @Patch('clients/:id/status')
  @ApiOperation({ summary: 'OAuth2 클라이언트 상태 업데이트' })
  @ApiResponse({
    status: 200,
    description: '클라이언트 상태가 성공적으로 업데이트됨',
  })
  @ApiResponse({
    status: 404,
    description: '클라이언트를 찾을 수 없음',
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
  ) {
    return this.authService.updateClientStatus(parseInt(id), body.isActive);
  }

  @Patch('clients/:id')
  @ApiOperation({ summary: 'OAuth2 클라이언트 정보 업데이트' })
  @ApiResponse({
    status: 200,
    description: '클라이언트 정보가 성공적으로 업데이트됨',
  })
  @ApiResponse({
    status: 404,
    description: '클라이언트를 찾을 수 없음',
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
  ) {
    return this.authService.updateClient(parseInt(id), updateData);
  }

  @Delete('clients/:id')
  @ApiOperation({ summary: 'OAuth2 클라이언트 삭제' })
  @ApiResponse({
    status: 200,
    description: '클라이언트가 성공적으로 삭제됨',
  })
  @ApiResponse({
    status: 404,
    description: '클라이언트를 찾을 수 없음',
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
  @UseGuards(JwtAuthGuard)
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
  async revokeToken(
    @Request() req: AuthenticatedRequest,
    @Param('id') tokenId: string,
  ) {
    await this.authService.revokeToken(req.user.id, parseInt(tokenId));
    return { message: 'Token revoked successfully' };
  }

  @Delete('tokens')
  @UseGuards(JwtAuthGuard)
  @ApiBearerAuth()
  @ApiOperation({ summary: '모든 사용자 토큰 취소' })
  @ApiResponse({
    status: 200,
    description: '모든 토큰이 성공적으로 취소됨',
  })
  async revokeAllUserTokens(@Request() req: AuthenticatedRequest) {
    await this.authService.revokeAllUserTokens(req.user.id);
    return { message: 'All user tokens revoked successfully' };
  }
}
