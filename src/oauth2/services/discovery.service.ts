import {
  Injectable,
  Logger,
  InternalServerErrorException,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { ScopeService } from '../scope.service';
import { OAuth2UserInfoBuilder } from '../utils/oauth2-userinfo.util';
import { OAUTH2_CONSTANTS } from '../../constants/oauth2.constants';
import { JWT_CONSTANTS } from '../../constants/jwt.constants';

/**
 * OpenID Connect Discovery Document Interface
 * RFC 8414 - OAuth 2.0 Authorization Server Metadata
 */
export interface OIDCDiscoveryDocument {
  /** 발급자 식별자 */
  issuer: string;
  /** 인증 엔드포인트 */
  authorization_endpoint: string;
  /** 토큰 엔드포인트 */
  token_endpoint: string;
  /** 사용자 정보 엔드포인트 */
  userinfo_endpoint: string;
  /** JWKS 엔드포인트 */
  jwks_uri: string;
  /** 지원하는 스코프 목록 */
  scopes_supported: string[];
  /** 지원하는 응답 타입 목록 */
  response_types_supported: string[];
  /** 지원하는 Grant 타입 목록 */
  grant_types_supported: string[];
  /** 지원하는 주체(Subject) 타입 목록 */
  subject_types_supported: string[];
  /** ID 토큰 서명 알고리즘 목록 */
  id_token_signing_alg_values_supported: string[];
  /** 토큰 엔드포인트 인증 방법 목록 */
  token_endpoint_auth_methods_supported: string[];
  /** 지원하는 클레임 목록 */
  claims_supported: string[];
  /** 요청 파라미터 지원 여부 */
  request_parameter_supported: boolean;
  /** 요청 URI 파라미터 지원 여부 */
  request_uri_parameter_supported: boolean;
  /** 요청 URI 등록 필요 여부 */
  require_request_uri_registration: boolean;
  /** 클레임 파라미터 지원 여부 */
  claims_parameter_supported?: boolean;
  /** PKCE 코드 챌린지 방법 지원 목록 */
  code_challenge_methods_supported?: string[];
  /** 토큰 취소 엔드포인트 */
  revocation_endpoint?: string;
  /** 토큰 조회 엔드포인트 */
  introspection_endpoint?: string;
}

/**
 * OpenID Connect Discovery 서비스
 * 시스템의 실제 구현을 기반으로 OIDC Discovery Document를 동적으로 생성합니다.
 */
@Injectable()
export class DiscoveryService {
  private readonly logger = new Logger(DiscoveryService.name);

  constructor(
    private readonly configService: ConfigService,
    private readonly scopeService: ScopeService,
  ) {}

  /**
   * OpenID Connect Discovery Document 생성
   * 실제 시스템 설정과 지원 기능을 반영하여 동적으로 생성합니다.
   * 생성된 문서는 내부적으로 검증되어 유효한 문서만 반환됩니다.
   */
  async generateDiscoveryDocument(): Promise<OIDCDiscoveryDocument> {
    try {
      const baseUrl = this.getBaseUrl();

      // 지원하는 스코프 목록을 동적으로 조회
      const supportedScopes = await this.getSupportedScopes();

      // 지원하는 클레임 목록을 동적으로 생성
      const supportedClaims = this.getSupportedClaims();

      // 지원하는 응답 타입 목록
      const supportedResponseTypes = this.getSupportedResponseTypes();

      // 지원하는 Grant 타입 목록
      const supportedGrantTypes = this.getSupportedGrantTypes();

      // ID 토큰 서명 알고리즘 목록
      const idTokenSigningAlgorithms = this.getIdTokenSigningAlgorithms();

      // 토큰 엔드포인트 인증 방법 목록
      const tokenEndpointAuthMethods = this.getTokenEndpointAuthMethods();

      const discoveryDocument: OIDCDiscoveryDocument = {
        issuer: baseUrl,
        authorization_endpoint: `${baseUrl}/oauth2/authorize`,
        token_endpoint: `${baseUrl}/oauth2/token`,
        userinfo_endpoint: `${baseUrl}/oauth2/userinfo`,
        jwks_uri: `${baseUrl}/.well-known/jwks.json`,
        scopes_supported: supportedScopes,
        response_types_supported: supportedResponseTypes,
        grant_types_supported: supportedGrantTypes,
        subject_types_supported: ['public'],
        id_token_signing_alg_values_supported: idTokenSigningAlgorithms,
        token_endpoint_auth_methods_supported: tokenEndpointAuthMethods,
        claims_supported: supportedClaims,
        request_parameter_supported: false,
        request_uri_parameter_supported: false,
        require_request_uri_registration: false,
        claims_parameter_supported: false,
        code_challenge_methods_supported: [...OAUTH2_CONSTANTS.PKCE_METHODS],
        revocation_endpoint: `${baseUrl}/oauth2/revoke`,
        introspection_endpoint: `${baseUrl}/oauth2/introspect`,
      };

      // 생성된 문서의 유효성 검사를 내부적으로 수행
      const isValid = this.validateDiscoveryDocument(discoveryDocument);
      if (!isValid) {
        throw new InternalServerErrorException(
          'Generated discovery document failed validation',
        );
      }

      return discoveryDocument;
    } catch (error) {
      if (error instanceof InternalServerErrorException) {
        // 유효성 검사 실패인 경우 그대로 재던짐
        throw error;
      }

      this.logger.error('Failed to generate OIDC Discovery Document', error);
      throw new InternalServerErrorException(
        'Failed to generate discovery document',
      );
    }
  }

  /**
   * 시스템의 기본 URL 조회
   */
  private getBaseUrl(): string {
    return (
      this.configService.get<string>('BACKEND_URL') ?? 'http://localhost:3000'
    );
  }

  /**
   * 지원하는 스코프 목록을 동적으로 조회
   */
  private async getSupportedScopes(): Promise<string[]> {
    try {
      const scopes = await this.scopeService.findAll();
      return scopes.map((scope) => scope.name);
    } catch (error) {
      this.logger.warn(
        'Failed to fetch scopes from database, using defaults',
        error,
      );
      // 기본 스코프 목록 반환
      return ['openid', 'profile', 'email'];
    }
  }

  /**
   * 지원하는 클레임 목록을 동적으로 생성
   * OAuth2UserInfoBuilder의 스코프 매핑을 기반으로 생성
   */
  private getSupportedClaims(): string[] {
    // OAuth2UserInfoBuilder에서 지원하는 모든 필드를 추출
    const supportedScopes = OAuth2UserInfoBuilder.getSupportedScopes();
    const allClaims = new Set<string>();

    // 항상 포함되는 기본 클레임
    allClaims.add('sub');
    allClaims.add('iss');
    allClaims.add('aud');
    allClaims.add('exp');
    allClaims.add('iat');
    allClaims.add('auth_time');

    // 각 스코프별로 지원하는 필드들을 수집
    for (const scope of supportedScopes) {
      const fields = OAuth2UserInfoBuilder.getFieldsForScope(scope);
      fields.forEach((field) => allClaims.add(field));
    }

    return Array.from(allClaims).sort();
  }

  /**
   * 지원하는 응답 타입 목록 조회
   */
  private getSupportedResponseTypes(): string[] {
    return [...OAUTH2_CONSTANTS.SUPPORTED_RESPONSE_TYPES];
  }

  /**
   * 지원하는 Grant 타입 목록 조회
   */
  private getSupportedGrantTypes(): string[] {
    return [...OAUTH2_CONSTANTS.SUPPORTED_GRANT_TYPES];
  }

  /**
   * ID 토큰 서명 알고리즘 목록 조회
   */
  private getIdTokenSigningAlgorithms(): string[] {
    return [JWT_CONSTANTS.ALGORITHMS.RS256];
  }

  /**
   * 토큰 엔드포인트 인증 방법 목록 조회
   */
  private getTokenEndpointAuthMethods(): string[] {
    return ['client_secret_basic', 'client_secret_post'];
  }

  /**
   * Discovery Document의 유효성 검사
   */
  validateDiscoveryDocument(document: OIDCDiscoveryDocument): boolean {
    try {
      // 필수 필드들이 모두 존재하는지 확인
      const requiredFields = [
        'issuer',
        'authorization_endpoint',
        'token_endpoint',
        'userinfo_endpoint',
        'jwks_uri',
        'scopes_supported',
        'response_types_supported',
        'grant_types_supported',
        'subject_types_supported',
        'id_token_signing_alg_values_supported',
        'token_endpoint_auth_methods_supported',
        'claims_supported',
      ];

      for (const field of requiredFields) {
        if (!(field in document)) {
          this.logger.error(
            `Missing required field in discovery document: ${field}`,
          );
          return false;
        }
      }

      // Issuer URL이 유효한지 확인
      if (!document.issuer || typeof document.issuer !== 'string') {
        this.logger.error('Invalid issuer URL in discovery document');
        return false;
      }

      // 엔드포인트 URL들이 유효한지 확인
      const urlFields = [
        'authorization_endpoint',
        'token_endpoint',
        'userinfo_endpoint',
        'jwks_uri',
      ];

      for (const field of urlFields) {
        const value = document[field as keyof OIDCDiscoveryDocument];
        if (!value || typeof value !== 'string') {
          this.logger.error(
            `Invalid URL field in discovery document: ${field}`,
          );
          return false;
        }
      }

      // 배열 필드들이 비어있지 않은지 확인
      const arrayFields = [
        'scopes_supported',
        'response_types_supported',
        'grant_types_supported',
        'subject_types_supported',
        'id_token_signing_alg_values_supported',
        'token_endpoint_auth_methods_supported',
        'claims_supported',
      ];

      for (const field of arrayFields) {
        const value = document[field as keyof OIDCDiscoveryDocument];
        if (!Array.isArray(value) || value.length === 0) {
          this.logger.error(
            `Invalid or empty array field in discovery document: ${field}`,
          );
          return false;
        }
      }

      // OpenID Connect 필수 스코프가 포함되어 있는지 확인
      if (!document.scopes_supported.includes('openid')) {
        this.logger.error('Discovery document must include "openid" scope');
        return false;
      }

      // Authorization Code Flow가 지원되는지 확인
      if (!document.response_types_supported.includes('code')) {
        this.logger.error(
          'Discovery document must support "code" response type',
        );
        return false;
      }

      if (!document.grant_types_supported.includes('authorization_code')) {
        this.logger.error(
          'Discovery document must support "authorization_code" grant type',
        );
        return false;
      }

      return true;
    } catch (error) {
      this.logger.error('Error validating discovery document', error);
      return false;
    }
  }
}
