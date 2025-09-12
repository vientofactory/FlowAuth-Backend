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
import { AuthService } from './auth.service';
import { CreateUserDto } from './dto/create-user.dto';
import { LoginDto } from './dto/login.dto';
import { CreateClientDto } from './dto/create-client.dto';

@Controller('auth')
@UseGuards(ThrottlerGuard)
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Post('register')
  async register(@Body() createUserDto: CreateUserDto) {
    return this.authService.register(createUserDto);
  }

  @Post('login')
  async login(@Body() loginDto: LoginDto) {
    const user = await this.authService.login(loginDto);
    // TODO: JWT 토큰 생성 및 반환
    return { user, message: 'Login successful' };
  }

  @Get('profile')
  async getProfile() {
    // TODO: JWT에서 사용자 ID 추출
    const userId = 1; // 임시
    return this.authService.findById(userId);
  }

  @Put('profile')
  async updateProfile(
    @Body() updateData: Partial<{ firstName: string; lastName: string }>,
  ) {
    // TODO: JWT에서 사용자 ID 추출
    const userId = 1; // 임시
    return this.authService.updateProfile(userId, updateData);
  }

  @Post('clients')
  async createClient(@Body() createClientDto: CreateClientDto) {
    return this.authService.createClient(createClientDto);
  }

  @Get('clients')
  async getClients() {
    return this.authService.getClients();
  }

  @Get('clients/:id')
  async getClientById(@Param('id') id: string) {
    return this.authService.getClientById(parseInt(id));
  }

  @Patch('clients/:id/status')
  async updateClientStatus(
    @Param('id') id: string,
    @Body() body: { isActive: boolean },
  ) {
    return this.authService.updateClientStatus(parseInt(id), body.isActive);
  }

  @Delete('clients/:id')
  async deleteClient(@Param('id') id: string) {
    await this.authService.deleteClient(parseInt(id));
    return { message: 'Client deleted successfully' };
  }
}
