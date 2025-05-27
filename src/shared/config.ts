/**
 * Configuration management for the Complete Arbitration Mesh
 */

import type { LogLevel } from './logger';

export interface ConfigOptions {
  logLevel?: LogLevel;
  apiVersion?: string;
  environment?: 'development' | 'staging' | 'production';
  database?: DatabaseConfig;
  redis?: RedisConfig;
  providers?: ProviderConfig[];
  collaboration?: CollaborationConfig;
  security?: SecurityConfig;
}

export interface DatabaseConfig {
  host: string;
  port: number;
  database: string;
  username: string;
  password: string;
  ssl: boolean;
}

export interface RedisConfig {
  host: string;
  port: number;
  password?: string;
  database: number;
}

export interface ProviderConfig {
  id: string;
  type: string;
  apiKey: string;
  endpoint?: string;
  enabled: boolean;
}

export interface CollaborationConfig {
  agentDiscoveryTimeout: number;
  maxConcurrentCollaborations: number;
  defaultTaskTimeout: number;
}

export interface SecurityConfig {
  jwtSecret: string;
  jwtExpirationTime: string;
  rateLimiting: {
    enabled: boolean;
    requestsPerMinute: number;
  };
  cors: {
    enabled: boolean;
    origins: string[];
  };
}

export class Config {
  public logLevel: LogLevel;
  public apiVersion: string;
  public environment: 'development' | 'staging' | 'production';
  public database?: DatabaseConfig;
  public redis?: RedisConfig;
  public providers: ProviderConfig[];
  public collaboration: CollaborationConfig;
  public security: SecurityConfig;

  constructor(options: ConfigOptions = {}) {
    this.logLevel = options.logLevel || this.getEnvLogLevel();
    this.apiVersion = options.apiVersion || '2.0';
    this.environment = options.environment || this.getEnvironment();
    this.database = options.database;
    this.redis = options.redis;
    this.providers = options.providers || [];
    this.collaboration = options.collaboration || this.getDefaultCollaborationConfig();
    this.security = options.security || this.getDefaultSecurityConfig();
  }

  update(options: Partial<ConfigOptions>): void {
    if (options.logLevel) this.logLevel = options.logLevel;
    if (options.apiVersion) this.apiVersion = options.apiVersion;
    if (options.environment) this.environment = options.environment;
    if (options.database) this.database = { ...this.database, ...options.database };
    if (options.redis) this.redis = { ...this.redis, ...options.redis };
    if (options.providers) this.providers = options.providers;
    if (options.collaboration) this.collaboration = { ...this.collaboration, ...options.collaboration };
    if (options.security) this.security = { ...this.security, ...options.security };
  }

  private getEnvLogLevel(): LogLevel {
    const level = process.env.LOG_LEVEL?.toLowerCase();
    if (level && ['debug', 'info', 'warn', 'error'].includes(level)) {
      return level as LogLevel;
    }
    return 'info';
  }

  private getEnvironment(): 'development' | 'staging' | 'production' {
    const env = process.env.NODE_ENV?.toLowerCase();
    if (env === 'development' || env === 'staging' || env === 'production') {
      return env;
    }
    return 'development';
  }

  private getDefaultCollaborationConfig(): CollaborationConfig {
    return {
      agentDiscoveryTimeout: parseInt(process.env.AGENT_DISCOVERY_TIMEOUT || '30000'),
      maxConcurrentCollaborations: parseInt(process.env.MAX_CONCURRENT_COLLABORATIONS || '100'),
      defaultTaskTimeout: parseInt(process.env.DEFAULT_TASK_TIMEOUT || '300000')
    };
  }

  private getDefaultSecurityConfig(): SecurityConfig {
    return {
      jwtSecret: process.env.JWT_SECRET || 'your-secret-key-change-in-production',
      jwtExpirationTime: process.env.JWT_EXPIRATION || '1h',
      rateLimiting: {
        enabled: process.env.RATE_LIMITING_ENABLED !== 'false',
        requestsPerMinute: parseInt(process.env.RATE_LIMIT_RPM || '100')
      },
      cors: {
        enabled: process.env.CORS_ENABLED !== 'false',
        origins: process.env.CORS_ORIGINS?.split(',') || ['*']
      }
    };
  }

  isDevelopment(): boolean {
    return this.environment === 'development';
  }

  isProduction(): boolean {
    return this.environment === 'production';
  }

  isStaging(): boolean {
    return this.environment === 'staging';
  }
}
