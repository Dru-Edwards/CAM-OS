/**
 * Complete Arbitration Mesh JavaScript/TypeScript SDK
 * 
 * This file contains the main SDK implementation for interacting with the CAM platform.
 */

export * from './client';
export * from './types';
export * from './errors';
export * from './utils';

// Version info
export const SDK_VERSION = '2.0.0';

// Default configuration
export const DEFAULT_CONFIG = {
  endpoint: 'https://api.cam.example.com',
  timeout: 30000,
  maxRetries: 3,
  retryDelay: 1000,
};

// Re-export the main client for convenience
export { CAMClient as default } from './client';
