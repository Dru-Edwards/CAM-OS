// Global test setup
export default async (): Promise<void> => {
  console.log('Setting up test environment...');
  
  // Set test environment variables
  process.env.NODE_ENV = 'test';
  process.env.LOG_LEVEL = 'error';
  
  // Initialize test database or external services if needed
  // This runs once before all tests
};
