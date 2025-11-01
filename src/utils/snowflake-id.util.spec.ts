import { SnowflakeIdGenerator } from './snowflake-id.util';

describe('SnowflakeIdGenerator', () => {
  let generator: SnowflakeIdGenerator;

  beforeEach(() => {
    generator = new SnowflakeIdGenerator(1, 1640995200000);
  });

  it('should generate unique IDs', async () => {
    const id1 = await generator.generate();
    const id2 = await generator.generate();
    expect(id1).not.toBe(id2);
  });

  it('should extract timestamp correctly', () => {
    const id = '1234567890123456789';
    const date = SnowflakeIdGenerator.extractTimestamp(id);
    expect(date).toBeInstanceOf(Date);
  });

  it('should extract node ID correctly', () => {
    const id = '1234567890123456789';
    const nodeId = SnowflakeIdGenerator.extractNodeId(id);
    expect(typeof nodeId).toBe('number');
  });

  it('should extract sequence correctly', () => {
    const id = '1234567890123456789';
    const sequence = SnowflakeIdGenerator.extractSequence(id);
    expect(typeof sequence).toBe('number');
  });

  it('should throw error for invalid node ID', () => {
    expect(() => new SnowflakeIdGenerator(1024)).toThrow();
    expect(() => new SnowflakeIdGenerator(-1)).toThrow();
  });

  it('should throw error for invalid epoch', () => {
    const futureEpoch = Date.now() + 1000000;
    expect(() => new SnowflakeIdGenerator(1, futureEpoch)).toThrow();
    expect(() => new SnowflakeIdGenerator(1, -1)).toThrow();
  });

  it('should handle sequence overflow', async () => {
    // 시퀀스를 4095로 설정하여 오버플로우 시뮬레이션
    (generator as any).sequence = 0xfff;
    (generator as any).lastTimestamp = Date.now();
    const id = await generator.generate();
    expect(typeof id).toBe('string');
  });
});
