import { Logger } from '../shared/logger.js';
import { CAMError } from '../shared/errors.js';
import { 
  AuthToken, 
  AuthRequest, 
  AuthResponse, 
  TokenValidationResult,
  AuthConfig,
  UserInfo,
  Permission
} from '../shared/types.js';
import crypto from 'crypto';
import jwt from 'jsonwebtoken';

/**
 * Authentication Service for Complete Arbitration Mesh
 * Handles both routing authentication (CAM Classic) and collaboration authentication (IACP)
 */
export class AuthenticationService {
  private readonly jwtSecret: string;
  private readonly tokenExpiry: string;
  private readonly logger: Logger;
  private activeSessions: Map<string, AuthToken> = new Map();
  private revokedTokens: Set<string> = new Set();

  constructor(config: AuthConfig) {
    this.jwtSecret = config.jwtSecret || this.generateSecret();
    this.tokenExpiry = config.tokenExpiry || '24h';
    this.logger = new Logger('AuthenticationService');
    
    this.logger.info('Authentication Service initialized', {
      tokenExpiry: this.tokenExpiry
    });
  }

  /**
   * Authenticate user and generate token
   */
  async authenticate(request: AuthRequest): Promise<AuthResponse> {
    try {
      this.logger.debug('Authentication attempt', { 
        clientId: request.clientId,
        type: request.type 
      });

      // Validate request
      this.validateAuthRequest(request);

      // Perform authentication based on type
      let userInfo: UserInfo;
      let permissions: Permission[];

      switch (request.type) {
        case 'api_key':
          ({ userInfo, permissions } = await this.authenticateApiKey(request));
          break;
        case 'oauth':
          ({ userInfo, permissions } = await this.authenticateOAuth(request));
          break;
        case 'certificate':
          ({ userInfo, permissions } = await this.authenticateCertificate(request));
          break;
        case 'collaboration':
          ({ userInfo, permissions } = await this.authenticateCollaboration(request));
          break;
        default:
          throw new CAMError('INVALID_AUTH_TYPE', `Unsupported authentication type: ${request.type}`);
      }

      // Generate JWT token
      const token = this.generateToken(userInfo, permissions);
      
      // Store active session
      this.activeSessions.set(token.id, token);

      this.logger.info('Authentication successful', {
        userId: userInfo.id,
        clientId: request.clientId,
        tokenId: token.id
      });

      return {
        success: true,
        token,
        userInfo,
        permissions,
        expiresAt: token.expiresAt
      };

    } catch (error) {
      this.logger.error('Authentication failed', { 
        clientId: request.clientId,
        error: error instanceof Error ? error.message : error 
      });
      
      return {
        success: false,
        error: error instanceof Error ? error.message : 'Authentication failed',
        errorCode: error instanceof CAMError ? error.code : 'AUTH_FAILED'
      };
    }
  }

  /**
   * Validate authentication token
   */
  validateToken(tokenString: string): TokenValidationResult {
    try {
      // Check if token is revoked
      if (this.revokedTokens.has(tokenString)) {
        return {
          valid: false,
          error: 'Token has been revoked',
          errorCode: 'TOKEN_REVOKED'
        };
      }

      // Verify JWT
      const decoded = jwt.verify(tokenString, this.jwtSecret) as any;
      
      // Check if session exists
      const session = this.activeSessions.get(decoded.jti);
      if (!session) {
        return {
          valid: false,
          error: 'Session not found',
          errorCode: 'SESSION_NOT_FOUND'
        };
      }

      // Check expiration
      if (Date.now() > new Date(session.expiresAt).getTime()) {
        this.activeSessions.delete(decoded.jti);
        return {
          valid: false,
          error: 'Token has expired',
          errorCode: 'TOKEN_EXPIRED'
        };
      }

      return {
        valid: true,
        token: session,
        userInfo: decoded.userInfo,
        permissions: decoded.permissions
      };

    } catch (error) {
      this.logger.debug('Token validation failed', { error });
      return {
        valid: false,
        error: 'Invalid token',
        errorCode: 'INVALID_TOKEN'
      };
    }
  }

  /**
   * Refresh authentication token
   */
  async refreshToken(tokenString: string): Promise<AuthResponse> {
    try {
      const validation = this.validateToken(tokenString);
      
      if (!validation.valid || !validation.token || !validation.userInfo) {
        throw new CAMError('INVALID_TOKEN', 'Cannot refresh invalid token');
      }

      // Generate new token
      const newToken = this.generateToken(validation.userInfo, validation.permissions || []);
      
      // Remove old session and add new one
      this.activeSessions.delete(validation.token.id);
      this.activeSessions.set(newToken.id, newToken);
      
      // Revoke old token
      this.revokedTokens.add(tokenString);

      this.logger.info('Token refreshed', {
        userId: validation.userInfo.id,
        oldTokenId: validation.token.id,
        newTokenId: newToken.id
      });

      return {
        success: true,
        token: newToken,
        userInfo: validation.userInfo,
        permissions: validation.permissions,
        expiresAt: newToken.expiresAt
      };

    } catch (error) {
      this.logger.error('Token refresh failed', { error });
      
      return {
        success: false,
        error: error instanceof Error ? error.message : 'Token refresh failed',
        errorCode: error instanceof CAMError ? error.code : 'REFRESH_FAILED'
      };
    }
  }

  /**
   * Revoke authentication token
   */
  revokeToken(tokenString: string): boolean {
    try {
      const decoded = jwt.decode(tokenString) as any;
      if (decoded?.jti) {
        this.activeSessions.delete(decoded.jti);
        this.revokedTokens.add(tokenString);
        
        this.logger.info('Token revoked', { tokenId: decoded.jti });
        return true;
      }
      return false;
    } catch {
      return false;
    }
  }

  /**
   * Check if user has specific permission
   */
  hasPermission(tokenString: string, requiredPermission: string): boolean {
    const validation = this.validateToken(tokenString);
    
    if (!validation.valid || !validation.permissions) {
      return false;
    }

    return validation.permissions.some(permission => 
      permission.resource === requiredPermission || 
      permission.resource === '*' ||
      requiredPermission.startsWith(permission.resource)
    );
  }

  /**
   * Get active sessions count
   */
  getActiveSessionsCount(): number {
    return this.activeSessions.size;
  }

  /**
   * Cleanup expired sessions
   */
  cleanupExpiredSessions(): void {
    const now = Date.now();
    let cleanedCount = 0;

    for (const [tokenId, session] of this.activeSessions.entries()) {
      if (new Date(session.expiresAt).getTime() < now) {
        this.activeSessions.delete(tokenId);
        cleanedCount++;
      }
    }

    if (cleanedCount > 0) {
      this.logger.info('Cleaned up expired sessions', { cleanedCount });
    }
  }

  /**
   * Generate JWT token
   */
  private generateToken(userInfo: UserInfo, permissions: Permission[]): AuthToken {
    const tokenId = crypto.randomUUID();
    const now = new Date();
    const expiresAt = new Date(now.getTime() + this.parseExpiry(this.tokenExpiry));

    const payload = {
      jti: tokenId,
      iat: Math.floor(now.getTime() / 1000),
      exp: Math.floor(expiresAt.getTime() / 1000),
      userInfo,
      permissions
    };

    const tokenString = jwt.sign(payload, this.jwtSecret);

    return {
      id: tokenId,
      token: tokenString,
      userId: userInfo.id,
      expiresAt: expiresAt.toISOString(),
      permissions
    };
  }

  /**
   * Authenticate using API key (CAM Classic method)
   */
  private async authenticateApiKey(request: AuthRequest): Promise<{ userInfo: UserInfo; permissions: Permission[] }> {
    // Simplified API key validation - in production, this would check against a database
    if (!request.credentials?.apiKey) {
      throw new CAMError('MISSING_API_KEY', 'API key is required');
    }

    // Mock validation - replace with actual API key verification
    const isValid = request.credentials.apiKey.startsWith('cam_');
    if (!isValid) {
      throw new CAMError('INVALID_API_KEY', 'Invalid API key format');
    }

    const userInfo: UserInfo = {
      id: crypto.createHash('sha256').update(request.credentials.apiKey).digest('hex').substring(0, 16),
      name: `API User ${request.clientId}`,
      email: `${request.clientId}@api.cam`,
      roles: ['api_user']
    };

    const permissions: Permission[] = [
      { resource: 'routing', actions: ['read', 'write'] },
      { resource: 'metrics', actions: ['read'] }
    ];

    return { userInfo, permissions };
  }

  /**
   * Authenticate using OAuth (IACP collaboration method)
   */
  private async authenticateOAuth(request: AuthRequest): Promise<{ userInfo: UserInfo; permissions: Permission[] }> {
    if (!request.credentials?.accessToken) {
      throw new CAMError('MISSING_ACCESS_TOKEN', 'OAuth access token is required');
    }

    // Mock OAuth validation - in production, this would verify with OAuth provider
    const userInfo: UserInfo = {
      id: crypto.randomUUID(),
      name: request.credentials.name || 'OAuth User',
      email: request.credentials.email || 'oauth@user.com',
      roles: ['collaboration_user']
    };

    const permissions: Permission[] = [
      { resource: 'collaboration', actions: ['read', 'write', 'create'] },
      { resource: 'routing', actions: ['read'] }
    ];

    return { userInfo, permissions };
  }

  /**
   * Authenticate using client certificate
   */
  private async authenticateCertificate(request: AuthRequest): Promise<{ userInfo: UserInfo; permissions: Permission[] }> {
    if (!request.credentials?.certificate) {
      throw new CAMError('MISSING_CERTIFICATE', 'Client certificate is required');
    }

    // Mock certificate validation
    const userInfo: UserInfo = {
      id: crypto.createHash('sha256').update(request.credentials.certificate).digest('hex').substring(0, 16),
      name: `Certificate User ${request.clientId}`,
      email: `${request.clientId}@cert.cam`,
      roles: ['enterprise_user']
    };

    const permissions: Permission[] = [
      { resource: '*', actions: ['*'] } // Full access for certificate auth
    ];

    return { userInfo, permissions };
  }

  /**
   * Authenticate for collaboration session (IACP specific)
   */
  private async authenticateCollaboration(request: AuthRequest): Promise<{ userInfo: UserInfo; permissions: Permission[] }> {
    if (!request.credentials?.sessionToken) {
      throw new CAMError('MISSING_SESSION_TOKEN', 'Collaboration session token is required');
    }

    const userInfo: UserInfo = {
      id: crypto.randomUUID(),
      name: request.credentials.agentName || 'Collaboration Agent',
      email: `${request.clientId}@collab.cam`,
      roles: ['agent']
    };

    const permissions: Permission[] = [
      { resource: 'collaboration', actions: ['read', 'write', 'coordinate'] },
      { resource: 'routing', actions: ['read'] },
      { resource: 'state', actions: ['read', 'write'] }
    ];

    return { userInfo, permissions };
  }

  /**
   * Validate authentication request
   */
  private validateAuthRequest(request: AuthRequest): void {
    if (!request.clientId) {
      throw new CAMError('MISSING_CLIENT_ID', 'Client ID is required');
    }

    if (!request.type) {
      throw new CAMError('MISSING_AUTH_TYPE', 'Authentication type is required');
    }

    if (!request.credentials) {
      throw new CAMError('MISSING_CREDENTIALS', 'Credentials are required');
    }
  }

  /**
   * Parse token expiry string to milliseconds
   */
  private parseExpiry(expiry: string): number {
    const unit = expiry.slice(-1);
    const value = parseInt(expiry.slice(0, -1));

    switch (unit) {
      case 's': return value * 1000;
      case 'm': return value * 60 * 1000;
      case 'h': return value * 60 * 60 * 1000;
      case 'd': return value * 24 * 60 * 60 * 1000;
      default: return 24 * 60 * 60 * 1000; // Default 24 hours
    }
  }

  /**
   * Generate a secure secret for JWT signing
   */
  private generateSecret(): string {
    return crypto.randomBytes(64).toString('hex');
  }

  /**
   * Shutdown and cleanup
   */
  shutdown(): void {
    this.activeSessions.clear();
    this.revokedTokens.clear();
    this.logger.info('Authentication Service shutdown complete');
  }
}
