// Vitest setup file
import 'reflect-metadata';
import { vi } from 'vitest';
import * as nodeCrypto from 'crypto';

// Set up environment variables for testing
process.env['NODE_ENV'] = 'test';
process.env['JWT_SECRET'] = 'test-jwt-secret';
process.env['OPENAI_API_KEY'] = 'sk-test-openai-key';
process.env['ANTHROPIC_API_KEY'] = 'sk-ant-test-anthropic-key';
process.env['GOOGLE_AI_API_KEY'] = 'test-google-ai-key';
process.env['AZURE_OPENAI_API_KEY'] = 'test-azure-openai-key';
process.env['AZURE_OPENAI_ENDPOINT'] = 'https://test-azure-openai-endpoint.com';
process.env['LOG_LEVEL'] = 'error';

// Polyfill crypto for Node.js environments to fix compatibility issues
if (typeof global.crypto === 'undefined') {
  // Use Node.js crypto module as a polyfill for the Web Crypto API
  global.crypto = {
    // Implement getRandomValues using Node.js crypto
    getRandomValues: function(array: Uint8Array): Uint8Array {
      const bytes = nodeCrypto.randomBytes(array.length);
      array.set(new Uint8Array(bytes));
      return array;
    },
    // Implement randomUUID using Node.js crypto
    randomUUID: function(): string {
      return nodeCrypto.randomUUID();
    }
  } as any;
}

// Suppress console output during tests
const originalConsole = { ...console };
global.console = {
  ...console,
  log: vi.fn(),
  debug: vi.fn(),
  info: vi.fn(),
  warn: vi.fn(),
  error: vi.fn()
};

// Store original console for debugging if needed
(global as any).originalConsole = originalConsole;

// Set test timeout
vi.setConfig({ testTimeout: 30000 });

