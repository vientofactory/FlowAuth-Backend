import { Controller, Get } from '@nestjs/common';
import { ApiTags, ApiOperation, ApiResponse } from '@nestjs/swagger';
import { AppService } from './app.service';
import { ServerStatusResponseDto } from './common/dto/response.dto';

@Controller()
@ApiTags('System')
export class AppController {
  constructor(private readonly appService: AppService) {}

  @Get()
  @ApiOperation({
    summary: '시스템 상태 확인',
    description: 'FlowAuth API 서버의 기본 상태를 확인합니다.',
  })
  @ApiResponse({
    status: 200,
    description: '서버 상태 정보',
    type: ServerStatusResponseDto,
  })
  getHello(): ServerStatusResponseDto {
    return this.appService.getHello();
  }
}
