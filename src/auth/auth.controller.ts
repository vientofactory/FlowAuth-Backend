import { Controller, Post, Body, Get, Param } from '@nestjs/common';
import { AuthService } from './auth.service';
import { CreateUserDto } from './dto/create-user.dto';
import { LoginDto } from './dto/login.dto';
import { CreateClientDto } from './dto/create-client.dto';

@Controller('auth')
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
}
