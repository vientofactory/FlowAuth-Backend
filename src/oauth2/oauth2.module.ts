import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { JwtModule } from '@nestjs/jwt';
import { OAuth2Controller } from './oauth2.controller';
import { OAuth2Service } from './oauth2.service';
import { AuthorizationCodeService } from './authorization-code.service';
import { TokenService } from './token.service';
import { ScopeService } from './scope.service';
import { User } from '../user/user.entity';
import { Client } from '../client/client.entity';
import { AuthorizationCode } from '../authorization-code/authorization-code.entity';
import { Token } from '../token/token.entity';
import { Scope } from '../scope/scope.entity';

@Module({
  imports: [
    TypeOrmModule.forFeature([User, Client, AuthorizationCode, Token, Scope]),
    JwtModule.register({
      secret: process.env.JWT_SECRET || 'your-secret-key',
      signOptions: { expiresIn: '1h' },
    }),
  ],
  controllers: [OAuth2Controller],
  providers: [
    OAuth2Service,
    AuthorizationCodeService,
    TokenService,
    ScopeService,
  ],
  exports: [OAuth2Service, TokenService],
})
export class OAuth2Module {}
