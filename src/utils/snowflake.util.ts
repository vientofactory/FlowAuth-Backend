export class SnowflakeIdGenerator {
  private epoch: number;
  private nodeId: number;
  private sequence: number;
  private lastTimestamp: number;

  constructor(
    nodeId: number = 1,
    epoch: number = 1640995200000, // 2022-01-01 기준
  ) {
    this.epoch = epoch;
    this.nodeId = nodeId & 0x3ff; // 10 bits
    this.sequence = 0;
    this.lastTimestamp = -1;
  }

  /**
   * Snowflake ID 생성
   * 64-bit ID 구조:
   * - 1 bit: 사용 안함 (항상 0)
   * - 41 bits: 타임스탬프 (ms)
   * - 10 bits: 노드 ID
   * - 12 bits: 시퀀스 번호
   */
  generate(): string {
    let timestamp = Date.now();

    if (timestamp < this.lastTimestamp) {
      throw new Error('Clock moved backwards. Refusing to generate id');
    }

    if (timestamp === this.lastTimestamp) {
      this.sequence = (this.sequence + 1) & 0xfff; // 12 bits
      if (this.sequence === 0) {
        // 시퀀스가 넘치면 다음 밀리초까지 대기
        timestamp = this.waitNextMillis(timestamp);
      }
    } else {
      this.sequence = 0;
    }

    this.lastTimestamp = timestamp;

    // ID 조합
    const timestampPart = BigInt(timestamp - this.epoch) << 22n; // 22 = 10 + 12
    const nodeIdPart = BigInt(this.nodeId) << 12n; // 12
    const sequencePart = BigInt(this.sequence);

    const id = timestampPart | nodeIdPart | sequencePart;

    return id.toString();
  }

  private waitNextMillis(lastTimestamp: number): number {
    let timestamp = Date.now();
    while (timestamp <= lastTimestamp) {
      timestamp = Date.now();
    }
    return timestamp;
  }

  /**
   * Snowflake ID에서 타임스탬프 추출
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
   * Snowflake ID에서 노드 ID 추출
   */
  static extractNodeId(snowflakeId: string): number {
    const id = BigInt(snowflakeId);
    return Number((id >> 12n) & 0x3ffn);
  }

  /**
   * Snowflake ID에서 시퀀스 번호 추출
   */
  static extractSequence(snowflakeId: string): number {
    const id = BigInt(snowflakeId);
    return Number(id & 0xfffn);
  }
}

// 전역 인스턴스
export const snowflakeGenerator = new SnowflakeIdGenerator();
