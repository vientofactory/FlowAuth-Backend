/**
 * Snowflake ID Generator Class
 * Generates 64-bit unique IDs based on Twitter's Snowflake algorithm.
 */
export class SnowflakeIdGenerator {
  private epoch: number;
  private nodeId: number;
  private sequence: number;
  private lastTimestamp: number;

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
    if (!Number.isInteger(nodeId) || nodeId < 0 || nodeId > 0x3ff) {
      throw new Error(
        `Node ID must be an integer between 0 and 1023, got ${nodeId}`,
      );
    }
    if (!Number.isInteger(epoch) || epoch < 0 || epoch > Date.now()) {
      throw new Error(
        `Epoch must be a positive integer and not in the future, got ${epoch}`,
      );
    }
    this.epoch = epoch;
    this.nodeId = nodeId;
    this.sequence = 0;
    this.lastTimestamp = -1;
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
    let timestamp = Date.now();

    if (timestamp < this.lastTimestamp) {
      // Clock skew handling: retry up to 10 times
      for (let i = 0; i < 10 && timestamp < this.lastTimestamp; i++) {
        timestamp = Date.now();
      }
      if (timestamp < this.lastTimestamp) {
        throw new Error(
          `Clock moved backwards by ${this.lastTimestamp - timestamp}ms. Refusing to generate id`,
        );
      }
    }

    if (timestamp === this.lastTimestamp) {
      this.sequence = (this.sequence + 1) & 0xfff; // 12 bits
      if (this.sequence === 0) {
        // Sequence overflow: wait for next millisecond
        timestamp = await this.waitNextMillis(timestamp);
      }
    } else {
      this.sequence = 0;
    }

    this.lastTimestamp = timestamp;

    const timestampPart = BigInt(timestamp - this.epoch) << 22n; // 22 = 10 + 12
    const nodeIdPart = BigInt(this.nodeId) << 12n; // 12
    const sequencePart = BigInt(this.sequence);

    const id = timestampPart | nodeIdPart | sequencePart;

    return id.toString();
  }

  private async waitNextMillis(lastTimestamp: number): Promise<number> {
    return new Promise((resolve) => {
      const check = () => {
        const timestamp = Date.now();
        if (timestamp > lastTimestamp) {
          resolve(timestamp);
        } else {
          setTimeout(check, 1); // Retry after 1ms
        }
      };
      check();
    });
  }

  /**
   * Extract timestamp from Snowflake ID
   */
  static extractTimestamp(
    snowflakeId: string,
    epoch: number = 1640995200000,
  ): Date {
    const id = BigInt(snowflakeId);
    const timestamp = Number(id >> 22n) + epoch;
    return new Date(timestamp);
  }

  /**
   * Extract node ID from Snowflake ID
   */
  static extractNodeId(snowflakeId: string): number {
    const id = BigInt(snowflakeId);
    return Number((id >> 12n) & 0x3ffn);
  }

  /**
   * Extract sequence number from Snowflake ID
   */
  static extractSequence(snowflakeId: string): number {
    const id = BigInt(snowflakeId);
    return Number(id & 0xfffn);
  }
}

// Global instance
export const snowflakeGenerator = new SnowflakeIdGenerator();
