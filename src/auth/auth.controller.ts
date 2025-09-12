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
import { ThrottlerGuard } from '@nestjs/throttler';
import { ApiTags, ApiOperation, ApiResponse, ApiBody } from '@nestjs/swagger';
import { AuthService } from './auth.service';
import { CreateUserDto } from './dto/create-user.dto';
import { LoginDto } from './dto/login.dto';
import { CreateClientDto } from './dto/create-client.dto';

@Controller('auth')
@UseGuards(ThrottlerGuard)
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
  async register(@Body() createUserDto: CreateUserDto) {
    return this.authService.register(createUserDto);
  }

  @Post('login')
  @ApiOperation({ summary: '사용자 로그인' })
  @ApiResponse({
    status: 200,
    description: '로그인 성공',
  })
  @ApiResponse({
    status: 401,
    description: '인증 실패',
  })
  @ApiBody({ type: LoginDto })
  async login(@Body() loginDto: LoginDto) {
    const user = await this.authService.login(loginDto);
    // TODO: JWT 토큰 생성 및 반환
    return { user, message: 'Login successful' };
  }

  @Get('profile')
  @ApiOperation({ summary: '사용자 프로필 조회' })
  @ApiResponse({
    status: 200,
    description: '프로필 정보 반환',
  })
  @ApiResponse({
    status: 401,
    description: '인증되지 않은 사용자',
  })
  async getProfile() {
    // TODO: JWT에서 사용자 ID 추출
    const userId = 1; // 임시
    return this.authService.findById(userId);
  }

  @Put('profile')
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
    @Body() updateData: Partial<{ firstName: string; lastName: string }>,
  ) {
    // TODO: JWT에서 사용자 ID 추출
    const userId = 1; // 임시
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
}
