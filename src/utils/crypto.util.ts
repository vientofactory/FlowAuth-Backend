import * as crypto from 'crypto';

/**
 * 암호화적으로 안전한 난수 생성 유틸리티
 */
export class CryptoUtils {
  /**
   * 암호화적으로 안전한 랜덤 문자열 생성
   * @param length 생성할 문자열 길이
   * @param charset 사용할 문자 집합 (기본값: 영문 대소문자 + 숫자)
   * @returns 랜덤 문자열
   */
  static generateRandomString(
    length: number,
    charset: string = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789',
  ): string {
    if (length <= 0) {
      throw new Error('Length must be greater than 0');
    }

    if (charset.length === 0) {
      throw new Error('Charset cannot be empty');
    }

    const randomBytes = crypto.randomBytes(length);
    let result = '';

    for (let i = 0; i < length; i++) {
      // crypto.randomBytes()로 생성된 바이트를 charset 인덱스로 변환
      result += charset.charAt(randomBytes[i] % charset.length);
    }

    return result;
  }

  /**
   * OAuth2 state 파라미터용 랜덤 문자열 생성
   * @param length 생성할 길이 (기본값: 32)
   * @returns 랜덤 state 문자열
   */
  static generateState(length: number = 32): string {
    return this.generateRandomString(length);
  }

  /**
   * PKCE code_verifier 생성
   * @returns base64url 인코딩된 code_verifier (43-128 글자)
   */
  static generateCodeVerifier(): string {
    const randomBytes = crypto.randomBytes(32);
    return randomBytes.toString('base64url');
  }

  /**
   * PKCE code_challenge 생성
   * @param codeVerifier code_verifier 값
   * @returns SHA256 해시된 code_challenge
   */
  static generateCodeChallenge(codeVerifier: string): string {
    const hash = crypto.createHash('sha256').update(codeVerifier).digest();
    return hash.toString('base64url');
  }

  /**
   * 지정된 범위의 랜덤 정수 생성
   * @param min 최소값 (포함)
   * @param max 최대값 (포함)
   * @returns 범위 내의 랜덤 정수
   */
  static randomInt(min: number, max: number): number {
    if (min > max) {
      throw new Error('min cannot be greater than max');
    }

    const range = max - min + 1;
    const randomBytes = crypto.randomBytes(4);
    const randomValue = randomBytes.readUInt32BE(0);

    return min + (randomValue % range);
  }

  /**
   * 암호화적으로 안전한 랜덤 바이트 생성
   * @param size 바이트 수
   * @returns Buffer 형태의 랜덤 바이트
   */
  static randomBytes(size: number): Buffer {
    return crypto.randomBytes(size);
  }
}
