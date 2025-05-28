/**
 * CAM Protocol Deployment Readiness Verification Script
 * 
 * This script checks if the CAM Protocol is ready for deployment by verifying:
 * 1. All required files and directories exist
 * 2. Package.json has the correct dependencies and scripts
 * 3. CI/CD workflows are properly configured
 * 4. Documentation is complete
 * 5. Legal and compliance documents are in place
 */

const fs = require('fs');
const path = require('path');
const { execSync } = require('child_process');

// Root directory of the project
const rootDir = path.resolve(__dirname, '..');

// Colors for console output
const colors = {
  reset: '\x1b[0m',
  red: '\x1b[31m',
  green: '\x1b[32m',
  yellow: '\x1b[33m',
  blue: '\x1b[34m',
  magenta: '\x1b[35m',
  cyan: '\x1b[36m',
  white: '\x1b[37m'
};

// Logging functions
const log = {
  info: (message) => console.log(`${colors.blue}[INFO]${colors.reset} ${message}`),
  success: (message) => console.log(`${colors.green}[SUCCESS]${colors.reset} ${message}`),
  warning: (message) => console.log(`${colors.yellow}[WARNING]${colors.reset} ${message}`),
  error: (message) => console.log(`${colors.red}[ERROR]${colors.reset} ${message}`),
  section: (message) => console.log(`\n${colors.cyan}=== ${message} ===${colors.reset}`)
};

// Results tracking
const results = {
  passed: 0,
  warnings: 0,
  failed: 0
};

// Check if a file or directory exists
function checkExists(relativePath, isDirectory = false, isRequired = true) {
  const fullPath = path.join(rootDir, relativePath);
  const exists = fs.existsSync(fullPath);
  const type = isDirectory ? 'Directory' : 'File';
  
  if (exists) {
    if (isDirectory === fs.statSync(fullPath).isDirectory()) {
      log.success(`${type} exists: ${relativePath}`);
      results.passed++;
      return true;
    } else {
      log.error(`Path exists but is ${isDirectory ? 'not a directory' : 'not a file'}: ${relativePath}`);
      results.failed++;
      return false;
    }
  } else {
    if (isRequired) {
      log.error(`${type} does not exist: ${relativePath}`);
      results.failed++;
    } else {
      log.warning(`Optional ${type.toLowerCase()} does not exist: ${relativePath}`);
      results.warnings++;
    }
    return false;
  }
}

// Check if a file contains specific content
function checkFileContent(relativePath, searchString, description) {
  const fullPath = path.join(rootDir, relativePath);
  
  if (!fs.existsSync(fullPath)) {
    log.error(`File does not exist: ${relativePath}`);
    results.failed++;
    return false;
  }
  
  const content = fs.readFileSync(fullPath, 'utf8');
  const hasContent = content.includes(searchString);
  
  if (hasContent) {
    log.success(`${description}: ${relativePath}`);
    results.passed++;
    return true;
  } else {
    log.error(`${description} not found in: ${relativePath}`);
    results.failed++;
    return false;
  }
}

// Check package.json
function checkPackageJson() {
  log.section('Checking package.json');
  
  const packageJsonPath = path.join(rootDir, 'package.json');
  if (!fs.existsSync(packageJsonPath)) {
    log.error('package.json does not exist');
    results.failed++;
    return;
  }
  
  try {
    const packageJson = JSON.parse(fs.readFileSync(packageJsonPath, 'utf8'));
    
    // Check version
    if (packageJson.version) {
      log.success(`Version is defined: ${packageJson.version}`);
      results.passed++;
    } else {
      log.error('Version is not defined in package.json');
      results.failed++;
    }
    
    // Check required scripts
    const requiredScripts = ['build', 'test', 'lint', 'dev'];
    for (const script of requiredScripts) {
      if (packageJson.scripts && packageJson.scripts[script]) {
        log.success(`Script exists: ${script}`);
        results.passed++;
      } else {
        log.error(`Script does not exist: ${script}`);
        results.failed++;
      }
    }
    
    // Check dependencies
    const requiredDeps = ['typescript', 'vite', 'vitest'];
    for (const dep of requiredDeps) {
      if (
        (packageJson.dependencies && packageJson.dependencies[dep]) ||
        (packageJson.devDependencies && packageJson.devDependencies[dep])
      ) {
        log.success(`Dependency exists: ${dep}`);
        results.passed++;
      } else {
        log.error(`Dependency does not exist: ${dep}`);
        results.failed++;
      }
    }
  } catch (error) {
    log.error(`Error parsing package.json: ${error.message}`);
    results.failed++;
  }
}

// Check CI/CD workflows
function checkCICD() {
  log.section('Checking CI/CD Workflows');
  
  // Check GitHub workflows
  checkExists('.github/workflows', true);
  checkExists('.github/workflows/ci.yml');
  checkExists('.github/workflows/deploy.yml');
  checkExists('.github/workflows/release.yml');
  
  // Check workflow content
  checkFileContent('.github/workflows/ci.yml', 'name: Continuous Integration', 'CI workflow configuration');
  checkFileContent('.github/workflows/deploy.yml', 'name: Deploy', 'Deploy workflow configuration');
  checkFileContent('.github/workflows/release.yml', 'name: Release', 'Release workflow configuration');
}

// Check documentation
function checkDocumentation() {
  log.section('Checking Documentation');
  
  // Check README
  checkExists('README.md');
  checkFileContent('README.md', 'Complete Arbitration Mesh', 'Project title');
  
  // Check docs directory
  checkExists('docs', true);
  checkExists('docs/api', true);
  checkExists('docs/api/README.md');
  checkExists('docs/architecture', true);
  checkExists('docs/architecture/README.md');
  checkExists('docs/guides', true);
  checkExists('docs/guides/quick-start.md');
  
  // Check legal documents
  checkExists('docs/legal', true);
  checkExists('docs/legal/PRIVACY_POLICY.md');
  checkExists('docs/legal/TERMS_OF_SERVICE.md');
  checkExists('docs/legal/GDPR_COMPLIANCE.md');
  checkExists('docs/legal/CCPA_COMPLIANCE.md');
  checkExists('docs/legal/DATA_PROCESSING_AGREEMENT.md');
  checkExists('docs/legal/ACCEPTABLE_USE_POLICY.md');
  checkExists('docs/legal/SERVICE_LEVEL_AGREEMENT.md');
  
  // Check other important docs
  checkExists('CONTRIBUTING.md');
  checkExists('SECURITY.md');
  checkExists('LICENSE', false, true);
}

// Check source code
function checkSourceCode() {
  log.section('Checking Source Code');
  
  // Check src directory
  checkExists('src', true);
  checkExists('src/index.ts');
  
  // Check tests directory
  checkExists('tests', true);
  checkExists('tests/benchmarks', true);
  checkExists('tests/benchmarks/cost-optimization-benchmark.ts');
  checkExists('tests/benchmarks/multi-agent-collaboration-benchmark.ts');
  
  // Check examples directory
  checkExists('examples', true);
  checkExists('examples/demonstration', true);
  checkExists('examples/demonstration/value-demonstration.ts');
}

// Check deployment readiness
function checkDeploymentReadiness() {
  log.section('Checking Deployment Readiness');
  
  // Check deployment docs
  checkExists('docs/DEPLOYMENT_READINESS.md');
  checkFileContent('docs/DEPLOYMENT_READINESS.md', 'CAM Protocol Deployment Readiness Checklist', 'Deployment readiness checklist');
  
  // Check security docs
  checkExists('SECURITY.md');
  checkFileContent('SECURITY.md', 'Security Pre-Launch Checklist', 'Security pre-launch checklist');
}

// Run all checks
function runAllChecks() {
  log.section('Starting Deployment Readiness Verification');
  
  checkPackageJson();
  checkCICD();
  checkDocumentation();
  checkSourceCode();
  checkDeploymentReadiness();
  
  // Print summary
  log.section('Verification Summary');
  log.success(`Passed: ${results.passed}`);
  log.warning(`Warnings: ${results.warnings}`);
  log.error(`Failed: ${results.failed}`);
  
  if (results.failed === 0) {
    if (results.warnings === 0) {
      log.success('All checks passed! The CAM Protocol is ready for deployment.');
    } else {
      log.warning('All critical checks passed, but there are some warnings to address before deployment.');
    }
  } else {
    log.error('Some checks failed. Please address the issues before proceeding with deployment.');
  }
}

// Run the verification
runAllChecks();
