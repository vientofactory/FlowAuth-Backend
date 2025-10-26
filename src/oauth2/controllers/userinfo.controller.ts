import { Controller, Get, Request, BadRequestException } from '@nestjs/common';
import {
  ApiTags,
  ApiOperation,
  ApiResponse,
  ApiBearerAuth,
} from '@nestjs/swagger';
import { UseGuards } from '@nestjs/common';
import { OAuth2Service } from '../oauth2.service';
import { OAuth2BearerGuard } from '../guards/oauth2-bearer.guard';
import { OAuth2ScopeGuard } from '../guards/oauth2-scope.guard';
import { RequireScopes } from '../decorators/require-scopes.decorator';
import { UserinfoResponseDto } from '../dto/response.dto';
import { OAuth2UserInfoBuilder } from '../utils/oauth2-userinfo.util';

interface OAuth2AuthenticatedRequest extends Request {
  user: {
    sub: string;
    scopes: string[];
  };
}

@Controller('oauth2')
@ApiTags('OAuth2 Flow')
export class UserInfoController {
  constructor(
    private readonly oauth2Service: OAuth2Service,
    private readonly userInfoBuilder: OAuth2UserInfoBuilder,
  ) {}

  @Get('userinfo')
  @UseGuards(OAuth2BearerGuard, OAuth2ScopeGuard)
  @RequireScopes('openid')
  @ApiBearerAuth('JWT-auth')
  @ApiOperation({
    summary: '사용자 정보 조회',
    description: `
OAuth2 Access Token을 사용하여 사용자 정보를 조회합니다.

**OIDC 스코프별 반환 정보:**
- openid 스코프: sub (사용자 식별자) - 필수
- profile 스코프: 이름, 사용자명, 프로필 URL, 아바타, 역할 등
- email 스코프: 이메일 주소 및 검증 상태

**필요한 스코프:** openid
    `,
  })
  @ApiResponse({
    status: 200,
    description: '사용자 정보',
    type: UserinfoResponseDto,
  })
  @ApiResponse({
    status: 401,
    description: '유효하지 않은 토큰',
  })
  @ApiResponse({
    status: 403,
    description: '권한 부족 (스코프 부족)',
  })
  async userinfo(
    @Request() req: OAuth2AuthenticatedRequest,
  ): Promise<UserinfoResponseDto> {
    if (req.user.sub === null) {
      throw new BadRequestException('User ID not available for this token');
    }

    const user = await this.oauth2Service.getUserInfo(req.user.sub);

    if (!user) {
      throw new BadRequestException('User not found');
    }

    // 토큰의 스코프에 따라 반환할 정보를 결정
    const userScopes: string[] = req.user.scopes || [];
    return this.userInfoBuilder.buildUserInfo(user, userScopes);
  }
}
