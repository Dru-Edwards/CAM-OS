// Test setup file
import 'reflect-metadata';

// Add Jest type declarations
declare global {
  namespace NodeJS {
    interface Global {
      console: Console;
    }
  }
  const jest: any;
}

// Mock environment variables
process.env['NODE_ENV'] = 'test';
process.env['JWT_SECRET'] = 'test-jwt-secret';
process.env['OPENAI_API_KEY'] = 'sk-test-openai-key';
process.env['ANTHROPIC_API_KEY'] = 'sk-ant-test-anthropic-key';

// Global test configuration
global.console = {
  ...console,
  // Suppress console.log during tests unless explicitly enabled
  log: jest.fn(),
  debug: jest.fn(),
  info: jest.fn(),
  warn: jest.fn(),
  error: jest.fn()
};

// Mock timers for consistent testing
jest.useFakeTimers();

// Increase timeout for async operations
jest.setTimeout(30000);
