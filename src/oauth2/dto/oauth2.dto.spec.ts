import { validate } from 'class-validator';
import { AuthorizeRequestDto } from './oauth2.dto';

describe('AuthorizeRequestDto', () => {
  it('should validate valid authorize request', async () => {
    const dto = new AuthorizeRequestDto();
    dto.response_type = 'code';
    dto.client_id = 'test-client';
    dto.redirect_uri = 'https://example.com/callback';
    dto.state = 'test-state';

    const errors = await validate(dto);
    expect(errors).toHaveLength(0);
  });

  it('should fail validation for missing response_type', async () => {
    const dto = new AuthorizeRequestDto();
    dto.client_id = 'test-client';
    dto.redirect_uri = 'https://example.com/callback';
    dto.state = 'test-state';

    const errors = await validate(dto);
    expect(errors).toHaveLength(1);
    expect(errors[0].property).toBe('response_type');
  });

  it('should fail validation for invalid response_type', async () => {
    const dto = new AuthorizeRequestDto();
    dto.response_type = 'invalid';
    dto.client_id = 'test-client';
    dto.redirect_uri = 'https://example.com/callback';
    dto.state = 'test-state';

    const errors = await validate(dto);
    expect(errors).toHaveLength(1);
    expect(errors[0].property).toBe('response_type');
  });

  it('should fail validation for missing client_id', async () => {
    const dto = new AuthorizeRequestDto();
    dto.response_type = 'code';
    dto.redirect_uri = 'https://example.com/callback';
    dto.state = 'test-state';

    const errors = await validate(dto);
    expect(errors).toHaveLength(1);
    expect(errors[0].property).toBe('client_id');
  });

  it('should fail validation for empty state', async () => {
    const dto = new AuthorizeRequestDto();
    dto.response_type = 'code';
    dto.client_id = 'test-client';
    dto.redirect_uri = 'https://example.com/callback';
    dto.state = '';

    const errors = await validate(dto);
    expect(errors).toHaveLength(1);
    expect(errors[0].property).toBe('state');
  });

  it('should validate with optional scope', async () => {
    const dto = new AuthorizeRequestDto();
    dto.response_type = 'code';
    dto.client_id = 'test-client';
    dto.redirect_uri = 'https://example.com/callback';
    dto.state = 'test-state';
    dto.scope = 'openid profile email';

    const errors = await validate(dto);
    expect(errors).toHaveLength(0);
  });

  it('should validate with PKCE parameters', async () => {
    const dto = new AuthorizeRequestDto();
    dto.response_type = 'code';
    dto.client_id = 'test-client';
    dto.redirect_uri = 'https://example.com/callback';
    dto.state = 'test-state';
    dto.code_challenge = 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM';
    dto.code_challenge_method = 'S256';

    const errors = await validate(dto);
    expect(errors).toHaveLength(0);
  });
});
