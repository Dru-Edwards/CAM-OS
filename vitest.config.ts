import { defineConfig } from 'vitest/config';
import { resolve } from 'path';

export default defineConfig({
  test: {
    environment: 'node',
    include: ['**/*.{test,spec}.{ts,tsx}'],
    exclude: ['node_modules', 'dist'],
    globals: true,
    setupFiles: ['./tests/vitest-setup.ts'],
    coverage: {
      provider: 'v8',
      reporter: ['text', 'lcov', 'html'],
      exclude: [
        'src/**/*.d.ts',
        'src/**/index.ts',
        'node_modules/**',
        'dist/**'
      ],
      thresholds: {
        branches: 80,
        functions: 80,
        lines: 80,
        statements: 80
      }
    },
    testTimeout: 30000
  },
  resolve: {
    alias: {
      '@': resolve(__dirname, './src'),
      '@/core': resolve(__dirname, './src/core'),
      '@/routing': resolve(__dirname, './src/routing'),
      '@/collaboration': resolve(__dirname, './src/collaboration'),
      '@/shared': resolve(__dirname, './src/shared')
    }
  }
});
