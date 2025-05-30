import { defineConfig } from 'vite';
import { resolve } from 'path';

export default defineConfig({
  build: {
    lib: {
      entry: resolve(__dirname, 'src/index.ts'),
      name: 'CAMProtocol',
      fileName: (format) => `cam-protocol.${format}.js`,
      formats: ['es', 'cjs']
    },
    rollupOptions: {
      external: [
        'fastify',
        'ioredis',
        'pg',
        'node:crypto',
        'node:fs',
        'node:path',
        'node:url',
        'crypto',
        'fs',
        'path',
        'url'
      ],
      output: {
        globals: {
          'fastify': 'fastify',
          'ioredis': 'Redis',
          'pg': 'pg'
        }
      }
    },
    target: 'node16',
    minify: false,
    sourcemap: true
  },
  resolve: {
    alias: {
      '@': resolve(__dirname, './src'),
      '@/core': resolve(__dirname, './src/core'),
      '@/routing': resolve(__dirname, './src/routing'),
      '@/collaboration': resolve(__dirname, './src/collaboration'),
      '@/shared': resolve(__dirname, './src/shared')
    }
  },
  define: {
    'process.env.NODE_ENV': JSON.stringify(process.env.NODE_ENV || 'production')
  }
});
