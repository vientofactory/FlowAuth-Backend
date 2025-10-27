import { Controller, Get } from '@nestjs/common';
import { ApiTags, ApiOperation, ApiResponse } from '@nestjs/swagger';
import {
  HealthCheckService,
  HealthCheck,
  TypeOrmHealthIndicator,
  MemoryHealthIndicator,
} from '@nestjs/terminus';
import { JwtTokenService } from '../oauth2/services/jwt-token.service';

@ApiTags('Health')
@Controller('health')
export class HealthController {
  constructor(
    private health: HealthCheckService,
    private db: TypeOrmHealthIndicator,
    private memory: MemoryHealthIndicator,
    private jwtTokenService: JwtTokenService,
  ) {}

  @Get()
  @HealthCheck()
  @ApiOperation({
    summary: 'Application health check',
    description: 'Checks the health of the application and its dependencies',
  })
  @ApiResponse({
    status: 200,
    description: 'Application is healthy',
  })
  @ApiResponse({
    status: 503,
    description: 'Application is unhealthy',
  })
  check() {
    return this.health.check([
      () => this.db.pingCheck('database'),
      () => this.memory.checkHeap('memory_heap', 150 * 1024 * 1024), // 150MB
      () => this.memory.checkRSS('memory_rss', 150 * 1024 * 1024), // 150MB
      async () => {
        try {
          // RSA key validation
          const privateKeyPem = this.jwtTokenService.getRsaPrivateKeyPem();
          if (!privateKeyPem) {
            return {
              rsa_keys: {
                status: 'down',
                message: 'RSA private key not configured',
              },
            };
          }

          // Try to create key object to validate format
          const crypto = await import('crypto');
          crypto.createPrivateKey(privateKeyPem);

          return {
            rsa_keys: {
              status: 'up',
              message: 'RSA keys loaded successfully',
            },
          };
        } catch (error) {
          return {
            rsa_keys: {
              status: 'down',
              message: `RSA key validation failed: ${error instanceof Error ? error.message : 'Unknown error'}`,
            },
          };
        }
      },
    ]);
  }
}
