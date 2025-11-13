import { Test, TestingModule } from '@nestjs/testing';
import { InternalServerErrorException } from '@nestjs/common';
import { DiscoveryController } from './discovery.controller';
import {
  DiscoveryService,
  OIDCDiscoveryDocument,
} from '../services/discovery.service';

describe('DiscoveryController', () => {
  let controller: DiscoveryController;
  let discoveryService: jest.Mocked<DiscoveryService>;

  const mockDiscoveryDocument: OIDCDiscoveryDocument = {
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

  beforeEach(async () => {
    const mockDiscoveryService = {
      generateDiscoveryDocument: jest.fn(),
    };

    const module: TestingModule = await Test.createTestingModule({
      controllers: [DiscoveryController],
      providers: [
        { provide: DiscoveryService, useValue: mockDiscoveryService },
      ],
    }).compile();

    controller = module.get<DiscoveryController>(DiscoveryController);
    discoveryService = module.get(DiscoveryService);
  });

  it('should be defined', () => {
    expect(controller).toBeDefined();
  });

  describe('getOpenIdConfiguration', () => {
    it('should return discovery document when service succeeds', async () => {
      // Arrange
      discoveryService.generateDiscoveryDocument.mockResolvedValue(
        mockDiscoveryDocument,
      );

      // Act
      const result = await controller.getOpenIdConfiguration();

      // Assert
      expect(result).toEqual(mockDiscoveryDocument);
      expect(
        discoveryService['generateDiscoveryDocument'],
      ).toHaveBeenCalledTimes(1);
    });

    it('should re-throw InternalServerErrorException from service', async () => {
      // Arrange
      const serviceError = new InternalServerErrorException(
        'Generated discovery document failed validation',
      );
      discoveryService.generateDiscoveryDocument.mockRejectedValue(
        serviceError,
      );

      // Act & Assert
      await expect(controller.getOpenIdConfiguration()).rejects.toThrow(
        InternalServerErrorException,
      );
      expect(
        discoveryService['generateDiscoveryDocument'],
      ).toHaveBeenCalledTimes(1);
    });

    it('should wrap unexpected errors in InternalServerErrorException', async () => {
      // Arrange
      const unexpectedError = new Error('Unexpected database error');
      discoveryService.generateDiscoveryDocument.mockRejectedValue(
        unexpectedError,
      );

      // Act & Assert
      await expect(controller.getOpenIdConfiguration()).rejects.toThrow(
        InternalServerErrorException,
      );
      await expect(controller.getOpenIdConfiguration()).rejects.toThrow(
        'Failed to generate OpenID Configuration',
      );
      expect(
        discoveryService['generateDiscoveryDocument'],
      ).toHaveBeenCalledTimes(2);
    });
  });
});
