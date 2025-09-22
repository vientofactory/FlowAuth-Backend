import { Injectable, Logger, OnModuleDestroy } from '@nestjs/common';

@Injectable()
export class AppService implements OnModuleDestroy {
  private readonly logger = new Logger(AppService.name);

  getHello(): { message: string } {
    return { message: 'Hello World!' };
  }

  onModuleDestroy(): void {
    this.logger.log('AppService is shutting down...');
    // Add any cleanup logic here if needed
  }
}
