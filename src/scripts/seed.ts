import { NestFactory } from '@nestjs/core';
import { Logger } from '@nestjs/common';
import { AppModule } from '../app.module';
import { SeedService } from '../database/seed.service';

async function bootstrap(): Promise<void> {
  const logger = new Logger('SeedScript');
  const app = await NestFactory.createApplicationContext(AppModule);
  const seedService = app.get(SeedService);

  try {
    await seedService.seedDatabase();
    logger.log('Seeding completed successfully!');
  } catch (error: unknown) {
    logger.error('Seeding failed:', error);
    process.exit(1);
  } finally {
    await app.close();
  }
}

void bootstrap();
