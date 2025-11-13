import { Test, TestingModule } from '@nestjs/testing';
import { ConfigService } from '@nestjs/config';
import { InternalServerErrorException } from '@nestjs/common';
import { DiscoveryService } from './discovery.service';
import { ScopeService } from '../scope.service';

describe('DiscoveryService', () => {
  let service: DiscoveryService;
  let configService: jest.Mocked<ConfigService>;
  let scopeService: jest.Mocked<ScopeService>;

  beforeEach(async () => {
    const mockConfigService = {
      get: jest.fn(),
    };

    const mockScopeService = {
      findAll: jest.fn(),
    };

    const module: TestingModule = await Test.createTestingModule({
      providers: [
        DiscoveryService,
        { provide: ConfigService, useValue: mockConfigService },
        { provide: ScopeService, useValue: mockScopeService },
      ],
    }).compile();

    service = module.get<DiscoveryService>(DiscoveryService);
    configService = module.get(ConfigService);
    scopeService = module.get(ScopeService);
  });

  it('should be defined', () => {
    expect(service).toBeDefined();
  });

  describe('generateDiscoveryDocument', () => {
    it('should generate a valid discovery document', async () => {
      // Arrange
      configService.get.mockReturnValue('https://auth.example.com');
      scopeService.findAll.mockResolvedValue([
        { name: 'openid' },
        { name: 'profile' },
        { name: 'email' },
      ] as any);

      // Act
      const result = await service.generateDiscoveryDocument();

      // Assert
      expect(result).toBeDefined();
      expect(result.issuer).toBe('https://auth.example.com');
      expect(result.authorization_endpoint).toBe(
        'https://auth.example.com/oauth2/authorize',
      );
      expect(result.token_endpoint).toBe(
        'https://auth.example.com/oauth2/token',
      );
      expect(result.userinfo_endpoint).toBe(
        'https://auth.example.com/oauth2/userinfo',
      );
      expect(result.jwks_uri).toBe(
        'https://auth.example.com/.well-known/jwks.json',
      );
      expect(result.scopes_supported).toContain('openid');
      expect(result.scopes_supported).toContain('profile');
      expect(result.scopes_supported).toContain('email');
    });

    it('should use fallback scopes when database query fails', async () => {
      // Arrange
      configService.get.mockReturnValue('https://auth.example.com');
      scopeService.findAll.mockRejectedValue(new Error('Database error'));

      // Act
      const result = await service.generateDiscoveryDocument();

      // Assert
      expect(result).toBeDefined();
      expect(result.scopes_supported).toEqual(['openid', 'profile', 'email']);
    });

    it('should throw InternalServerErrorException when validation fails', async () => {
      // Arrange
      configService.get.mockReturnValue('https://auth.example.com');
      scopeService.findAll.mockResolvedValue([]);

      // Act & Assert
      await expect(service.generateDiscoveryDocument()).rejects.toThrow(
        InternalServerErrorException,
      );
    });

    it('should throw InternalServerErrorException when configuration is invalid', async () => {
      // Arrange
      configService.get.mockReturnValue(''); // Invalid URL
      scopeService.findAll.mockResolvedValue([{ name: 'openid' }] as any);

      // Act & Assert
      await expect(service.generateDiscoveryDocument()).rejects.toThrow(
        InternalServerErrorException,
      );
    });
  });

  describe('validateDiscoveryDocument', () => {
    it('should validate a valid discovery document', () => {
      // Arrange
      const validDocument = {
        issuer: 'https://auth.example.com',
        authorization_endpoint: 'https://auth.example.com/oauth2/authorize',
        token_endpoint: 'https://auth.example.com/oauth2/token',
        userinfo_endpoint: 'https://auth.example.com/oauth2/userinfo',
        jwks_uri: 'https://auth.example.com/.well-known/jwks.json',
        scopes_supported: ['openid', 'profile', 'email'],
        response_types_supported: ['code', 'token', 'id_token'],
        grant_types_supported: ['authorization_code', 'refresh_token'],
        subject_types_supported: ['public'],
        id_token_signing_alg_values_supported: ['RS256'],
        token_endpoint_auth_methods_supported: ['client_secret_basic'],
        claims_supported: ['sub', 'name', 'email'],
        request_parameter_supported: false,
        request_uri_parameter_supported: false,
        require_request_uri_registration: false,
      };

      // Act
      const result = service.validateDiscoveryDocument(validDocument);

      // Assert
      expect(result).toBe(true);
    });

    it('should reject document missing required fields', () => {
      // Arrange
      const invalidDocument = {
        issuer: 'https://auth.example.com',
        // Missing other required fields
      };

      // Act
      const result = service.validateDiscoveryDocument(invalidDocument as any);

      // Assert
      expect(result).toBe(false);
    });

    it('should reject document with empty array fields', () => {
      // Arrange
      const invalidDocument = {
        issuer: 'https://auth.example.com',
        authorization_endpoint: 'https://auth.example.com/oauth2/authorize',
        token_endpoint: 'https://auth.example.com/oauth2/token',
        userinfo_endpoint: 'https://auth.example.com/oauth2/userinfo',
        jwks_uri: 'https://auth.example.com/.well-known/jwks.json',
        scopes_supported: [], // Empty array
        response_types_supported: ['code'],
        grant_types_supported: ['authorization_code'],
        subject_types_supported: ['public'],
        id_token_signing_alg_values_supported: ['RS256'],
        token_endpoint_auth_methods_supported: ['client_secret_basic'],
        claims_supported: ['sub'],
        request_parameter_supported: false,
        request_uri_parameter_supported: false,
        require_request_uri_registration: false,
      };

      // Act
      const result = service.validateDiscoveryDocument(invalidDocument);

      // Assert
      expect(result).toBe(false);
    });

    it('should reject document without openid scope', () => {
      // Arrange
      const invalidDocument = {
        issuer: 'https://auth.example.com',
        authorization_endpoint: 'https://auth.example.com/oauth2/authorize',
        token_endpoint: 'https://auth.example.com/oauth2/token',
        userinfo_endpoint: 'https://auth.example.com/oauth2/userinfo',
        jwks_uri: 'https://auth.example.com/.well-known/jwks.json',
        scopes_supported: ['profile', 'email'], // Missing 'openid'
        response_types_supported: ['code'],
        grant_types_supported: ['authorization_code'],
        subject_types_supported: ['public'],
        id_token_signing_alg_values_supported: ['RS256'],
        token_endpoint_auth_methods_supported: ['client_secret_basic'],
        claims_supported: ['sub'],
        request_parameter_supported: false,
        request_uri_parameter_supported: false,
        require_request_uri_registration: false,
      };

      // Act
      const result = service.validateDiscoveryDocument(invalidDocument);

      // Assert
      expect(result).toBe(false);
    });

    it('should reject document without authorization code flow support', () => {
      // Arrange
      const invalidDocument = {
        issuer: 'https://auth.example.com',
        authorization_endpoint: 'https://auth.example.com/oauth2/authorize',
        token_endpoint: 'https://auth.example.com/oauth2/token',
        userinfo_endpoint: 'https://auth.example.com/oauth2/userinfo',
        jwks_uri: 'https://auth.example.com/.well-known/jwks.json',
        scopes_supported: ['openid', 'profile', 'email'],
        response_types_supported: ['token'], // Missing 'code'
        grant_types_supported: ['implicit'], // Missing 'authorization_code'
        subject_types_supported: ['public'],
        id_token_signing_alg_values_supported: ['RS256'],
        token_endpoint_auth_methods_supported: ['client_secret_basic'],
        claims_supported: ['sub'],
        request_parameter_supported: false,
        request_uri_parameter_supported: false,
        require_request_uri_registration: false,
      };

      // Act
      const result = service.validateDiscoveryDocument(invalidDocument);

      // Assert
      expect(result).toBe(false);
    });
  });
});
