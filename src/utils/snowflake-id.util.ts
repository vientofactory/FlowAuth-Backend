import {
  SnowflakeIdGenerator as BaseSnowflakeIdGenerator,
  extractTimestamp as baseExtractTimestamp,
  extractNodeId as baseExtractNodeId,
  extractSequence as baseExtractSequence,
} from 'snowflake-id-node';

/**
 * Snowflake ID Generator Class
 * Wrapper around snowflake-id-node library to maintain compatibility with existing API
 */
export class SnowflakeIdGenerator {
  private generator: BaseSnowflakeIdGenerator;

  /**
   * SnowflakeIdGenerator constructor
   * @param nodeId Node ID (0-1023 range, default: NODE_ID env var or 1)
   * @param epoch Epoch timestamp in milliseconds (default: 2022-01-01)
   * @throws {Error} If node ID is out of range or epoch is invalid
   */
  constructor(
    nodeId: number = parseInt(process.env.NODE_ID ?? '1', 10),
    epoch: number = 1640995200000, // 2022-01-01
  ) {
    this.generator = new BaseSnowflakeIdGenerator({
      nodeId,
      epoch,
    });
  }

  /**
   * Generate Snowflake ID (async)
   * 64-bit ID structure:
   * - 1 bit: unused (always 0)
   * - 41 bits: timestamp (ms)
   * - 10 bits: node ID
   * - 12 bits: sequence number
   * @returns Generated Snowflake ID as string
   * @throws {Error} If clock moved backwards and retries failed
   */
  async generate(): Promise<string> {
    // The underlying generate() returns a Promise<string>
    return this.generator.generate();
  }

  /**
   * Extract timestamp from Snowflake ID
   */
  static extractTimestamp(
    snowflakeId: string,
    epoch: number = 1640995200000,
  ): Date {
    return baseExtractTimestamp(snowflakeId, epoch);
  }

  /**
   * Extract node ID from Snowflake ID
   */
  static extractNodeId(snowflakeId: string): number {
    return baseExtractNodeId(snowflakeId);
  }

  /**
   * Extract sequence number from Snowflake ID
   */
  static extractSequence(snowflakeId: string): number {
    return baseExtractSequence(snowflakeId);
  }
}

// Global instance
export const snowflakeGenerator = new SnowflakeIdGenerator();
