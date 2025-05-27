import { AuthenticationService } from '../../src/core/auth-service';
import { CAMError } from '../../src/shared/errors';
import jwt from 'jsonwebtoken';

describe('AuthenticationService', () => {
  let authService: AuthenticationService;
  const mockConfig = {
    secret: 'test-secret-key',
    expiresIn: '1h',
    issuer: 'cam-test',
    audience: 'cam-api-test',
    refreshTokenExpiry: '7d'
  };

  beforeEach(() => {
    authService = new AuthenticationService(mockConfig);
  });

  describe('Token Generation', () => {
    it('should generate valid JWT token for API key authentication', async () => {
      const authRequest = {
        type: 'api-key' as const,
        credentials: {
          apiKey: 'test-api-key-123',
          userId: 'user-123'
        }
      };

      const response = await authService.authenticate(authRequest);

      expect(response.success).toBe(true);
      expect(response.token).toBeDefined();
      expect(response.expiresIn).toBe(3600);
      expect(response.userInfo).toEqual({
        id: 'user-123',
        type: 'api-key',
        permissions: ['route', 'collaborate']
      });

      // Verify token is valid JWT
      const decoded = jwt.verify(response.token, mockConfig.secret) as any;
      expect(decoded.userId).toBe('user-123');
      expect(decoded.type).toBe('api-key');
    });

    it('should generate token for OAuth authentication', async () => {
      const authRequest = {
        type: 'oauth' as const,
        credentials: {
          provider: 'google',
          accessToken: 'oauth-access-token',
          userId: 'oauth-user-123',
          email: 'user@example.com'
        }
      };

      const response = await authService.authenticate(authRequest);

      expect(response.success).toBe(true);
      expect(response.token).toBeDefined();
      expect(response.userInfo?.id).toBe('oauth-user-123');
      expect(response.userInfo?.email).toBe('user@example.com');
    });

    it('should generate token for certificate authentication', async () => {
      const authRequest = {
        type: 'certificate' as const,
        credentials: {
          certificate: 'base64-cert-data',
          privateKey: 'base64-key-data',
          userId: 'cert-user-123'
        }
      };

      const response = await authService.authenticate(authRequest);

      expect(response.success).toBe(true);
      expect(response.token).toBeDefined();
      expect(response.userInfo?.type).toBe('certificate');
    });

    it('should generate token for collaboration authentication', async () => {
      const authRequest = {
        type: 'collaboration' as const,
        credentials: {
          agentId: 'agent-123',
          capabilities: ['data-analysis', 'reporting'],
          collaborationId: 'collab-456'
        }
      };

      const response = await authService.authenticate(authRequest);

      expect(response.success).toBe(true);
      expect(response.token).toBeDefined();
      expect(response.userInfo?.id).toBe('agent-123');
      expect(response.userInfo?.type).toBe('collaboration');
      expect(response.userInfo?.capabilities).toEqual(['data-analysis', 'reporting']);
    });
  });

  describe('Token Validation', () => {
    it('should validate correct token', async () => {
      // First generate a token
      const authRequest = {
        type: 'api-key' as const,
        credentials: {
          apiKey: 'test-api-key',
          userId: 'user-123'
        }
      };

      const authResponse = await authService.authenticate(authRequest);
      
      // Then validate it
      const validation = await authService.validateToken(authResponse.token);

      expect(validation.valid).toBe(true);
      expect(validation.userInfo?.id).toBe('user-123');
      expect(validation.userInfo?.type).toBe('api-key');
      expect(validation.permissions).toContain('route');
      expect(validation.permissions).toContain('collaborate');
    });

    it('should reject invalid token', async () => {
      const validation = await authService.validateToken('invalid-token');

      expect(validation.valid).toBe(false);
      expect(validation.error).toBeDefined();
      expect(validation.userInfo).toBeUndefined();
    });

    it('should reject expired token', async () => {
      // Create expired token manually
      const expiredToken = jwt.sign(
        { userId: 'user-123', type: 'api-key' },
        mockConfig.secret,
        { expiresIn: '-1h' } // Expired 1 hour ago
      );

      const validation = await authService.validateToken(expiredToken);

      expect(validation.valid).toBe(false);
      expect(validation.error).toContain('expired');
    });

    it('should reject token with wrong secret', async () => {
      const wrongToken = jwt.sign(
        { userId: 'user-123', type: 'api-key' },
        'wrong-secret',
        { expiresIn: '1h' }
      );

      const validation = await authService.validateToken(wrongToken);

      expect(validation.valid).toBe(false);
      expect(validation.error).toBeDefined();
    });
  });

  describe('Refresh Token Management', () => {
    it('should generate and validate refresh tokens', async () => {
      const authRequest = {
        type: 'api-key' as const,
        credentials: {
          apiKey: 'test-api-key',
          userId: 'user-123'
        }
      };

      const authResponse = await authService.authenticate(authRequest);
      expect(authResponse.refreshToken).toBeDefined();

      const newTokenResponse = await authService.refreshToken(authResponse.refreshToken!);
      
      expect(newTokenResponse.success).toBe(true);
      expect(newTokenResponse.token).toBeDefined();
      expect(newTokenResponse.token).not.toBe(authResponse.token);
    });

    it('should reject invalid refresh token', async () => {
      await expect(
        authService.refreshToken('invalid-refresh-token')
      ).rejects.toThrow(CAMError);
    });
  });

  describe('Token Revocation', () => {
    it('should revoke token successfully', async () => {
      const authRequest = {
        type: 'api-key' as const,
        credentials: {
          apiKey: 'test-api-key',
          userId: 'user-123'
        }
      };

      const authResponse = await authService.authenticate(authRequest);
      
      // Revoke the token
      await authService.revokeToken(authResponse.token);

      // Validation should now fail
      const validation = await authService.validateToken(authResponse.token);
      expect(validation.valid).toBe(false);
      expect(validation.error).toContain('revoked');
    });

    it('should handle revocation of non-existent token', async () => {
      await expect(
        authService.revokeToken('non-existent-token')
      ).rejects.toThrow(CAMError);
    });
  });

  describe('Session Management', () => {
    it('should create and retrieve session', async () => {
      const sessionData = {
        userId: 'user-123',
        metadata: { loginTime: Date.now() }
      };

      const sessionId = await authService.createSession(sessionData);
      expect(sessionId).toBeDefined();

      const retrievedSession = await authService.getSession(sessionId);
      expect(retrievedSession?.userId).toBe('user-123');
      expect(retrievedSession?.metadata).toEqual(sessionData.metadata);
    });

    it('should update session data', async () => {
      const sessionData = {
        userId: 'user-123',
        metadata: { loginTime: Date.now() }
      };

      const sessionId = await authService.createSession(sessionData);
      
      const updatedData = {
        userId: 'user-123',
        metadata: { 
          loginTime: sessionData.metadata.loginTime,
          lastActivity: Date.now()
        }
      };

      await authService.updateSession(sessionId, updatedData);

      const retrievedSession = await authService.getSession(sessionId);
      expect(retrievedSession?.metadata.lastActivity).toBeDefined();
    });

    it('should delete session', async () => {
      const sessionData = {
        userId: 'user-123',
        metadata: { loginTime: Date.now() }
      };

      const sessionId = await authService.createSession(sessionData);
      await authService.deleteSession(sessionId);

      const retrievedSession = await authService.getSession(sessionId);
      expect(retrievedSession).toBeNull();
    });
  });

  describe('Permission Handling', () => {
    it('should check permissions correctly', async () => {
      const authRequest = {
        type: 'api-key' as const,
        credentials: {
          apiKey: 'test-api-key',
          userId: 'user-123'
        }
      };

      const authResponse = await authService.authenticate(authRequest);
      const validation = await authService.validateToken(authResponse.token);

      expect(authService.hasPermission(validation.permissions || [], 'route')).toBe(true);
      expect(authService.hasPermission(validation.permissions || [], 'collaborate')).toBe(true);
      expect(authService.hasPermission(validation.permissions || [], 'admin')).toBe(false);
    });

    it('should handle collaboration-specific permissions', async () => {
      const authRequest = {
        type: 'collaboration' as const,
        credentials: {
          agentId: 'agent-123',
          capabilities: ['data-analysis'],
          collaborationId: 'collab-456'
        }
      };

      const authResponse = await authService.authenticate(authRequest);
      const validation = await authService.validateToken(authResponse.token);

      expect(validation.permissions).toContain('collaborate');
      expect(validation.userInfo?.capabilities).toContain('data-analysis');
    });
  });

  describe('Error Handling', () => {
    it('should handle missing credentials', async () => {
      const authRequest = {
        type: 'api-key' as const,
        credentials: {} as any
      };

      await expect(
        authService.authenticate(authRequest)
      ).rejects.toThrow(CAMError);
    });

    it('should handle invalid authentication type', async () => {
      const authRequest = {
        type: 'invalid-type' as any,
        credentials: {
          apiKey: 'test-key'
        }
      };

      await expect(
        authService.authenticate(authRequest)
      ).rejects.toThrow(CAMError);
    });

    it('should handle malformed tokens', async () => {
      const malformedTokens = [
        '',
        'not.a.token',
        'header.payload', // Missing signature
        'invalid-jwt-format'
      ];

      for (const token of malformedTokens) {
        const validation = await authService.validateToken(token);
        expect(validation.valid).toBe(false);
        expect(validation.error).toBeDefined();
      }
    });
  });

  describe('Security Features', () => {
    it('should include security headers in tokens', async () => {
      const authRequest = {
        type: 'api-key' as const,
        credentials: {
          apiKey: 'test-api-key',
          userId: 'user-123'
        }
      };

      const response = await authService.authenticate(authRequest);
      const decoded = jwt.decode(response.token, { complete: true }) as any;

      expect(decoded.header.alg).toBe('HS256');
      expect(decoded.payload.iss).toBe(mockConfig.issuer);
      expect(decoded.payload.aud).toBe(mockConfig.audience);
      expect(decoded.payload.iat).toBeDefined();
      expect(decoded.payload.exp).toBeDefined();
    });

    it('should prevent token reuse after revocation', async () => {
      const authRequest = {
        type: 'api-key' as const,
        credentials: {
          apiKey: 'test-api-key',
          userId: 'user-123'
        }
      };

      const authResponse = await authService.authenticate(authRequest);
      
      // First validation should succeed
      let validation = await authService.validateToken(authResponse.token);
      expect(validation.valid).toBe(true);

      // Revoke token
      await authService.revokeToken(authResponse.token);

      // Subsequent validations should fail
      validation = await authService.validateToken(authResponse.token);
      expect(validation.valid).toBe(false);
    });
  });

  describe('Performance', () => {
    it('should handle multiple concurrent authentications', async () => {
      const promises = [];
      
      for (let i = 0; i < 10; i++) {
        promises.push(
          authService.authenticate({
            type: 'api-key',
            credentials: {
              apiKey: `test-key-${i}`,
              userId: `user-${i}`
            }
          })
        );
      }

      const responses = await Promise.all(promises);
      
      expect(responses).toHaveLength(10);
      responses.forEach((response, index) => {
        expect(response.success).toBe(true);
        expect(response.userInfo?.id).toBe(`user-${index}`);
      });
    });

    it('should handle multiple concurrent validations', async () => {
      // First create a token
      const authResponse = await authService.authenticate({
        type: 'api-key',
        credentials: {
          apiKey: 'test-key',
          userId: 'user-123'
        }
      });

      // Then validate it multiple times concurrently
      const promises = [];
      for (let i = 0; i < 10; i++) {
        promises.push(authService.validateToken(authResponse.token));
      }

      const validations = await Promise.all(promises);
      
      expect(validations).toHaveLength(10);
      validations.forEach(validation => {
        expect(validation.valid).toBe(true);
        expect(validation.userInfo?.id).toBe('user-123');
      });
    });
  });
});
