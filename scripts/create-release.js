#!/usr/bin/env node
/**
 * Script to create an official tagged release for the CAM Protocol
 * 
 * Usage: node scripts/create-release.js [--major|--minor|--patch] [--dry-run]
 */

const { execSync } = require('child_process');
const fs = require('fs');
const path = require('path');
const readline = require('readline');

// Parse command line arguments
const args = process.argv.slice(2);
const isDryRun = args.includes('--dry-run');
const versionBump = args.find(arg => ['--major', '--minor', '--patch'].includes(arg)) || '--patch';

// Create readline interface for user input
const rl = readline.createInterface({
  input: process.stdin,
  output: process.stdout
});

// Read current package.json
const packageJsonPath = path.join(__dirname, '..', 'package.json');
const packageJson = JSON.parse(fs.readFileSync(packageJsonPath, 'utf8'));
const currentVersion = packageJson.version;

// Calculate new version based on the bump type
function getNewVersion(currentVersion, bumpType) {
  const [major, minor, patch] = currentVersion.split('.').map(Number);
  
  switch (bumpType) {
    case '--major':
      return `${major + 1}.0.0`;
    case '--minor':
      return `${major}.${minor + 1}.0`;
    case '--patch':
    default:
      return `${major}.${minor}.${patch + 1}`;
  }
}

const newVersion = getNewVersion(currentVersion, versionBump);

// Main function
async function createRelease() {
  console.log(`Current version: ${currentVersion}`);
  console.log(`New version: ${newVersion}`);
  console.log(`Dry run: ${isDryRun ? 'Yes' : 'No'}`);
  
  // Ask for confirmation
  const answer = await new Promise(resolve => {
    rl.question('Do you want to continue? (y/n): ', resolve);
  });
  
  if (answer.toLowerCase() !== 'y') {
    console.log('Release creation cancelled.');
    rl.close();
    return;
  }
  
  try {
    // Step 1: Make sure the working directory is clean
    console.log('\nChecking git status...');
    const gitStatus = execSync('git status --porcelain').toString().trim();
    
    if (gitStatus) {
      console.error('Error: Working directory is not clean. Commit or stash changes first.');
      rl.close();
      return;
    }
    
    // Step 2: Pull latest changes
    console.log('\nPulling latest changes...');
    if (!isDryRun) {
      execSync('git pull', { stdio: 'inherit' });
    }
    
    // Step 3: Update version in package.json
    console.log(`\nUpdating version to ${newVersion} in package.json...`);
    if (!isDryRun) {
      packageJson.version = newVersion;
      fs.writeFileSync(packageJsonPath, JSON.stringify(packageJson, null, 2) + '\n');
    }
    
    // Step 4: Create CHANGELOG entry
    console.log('\nCreating CHANGELOG entry...');
    const changelogPath = path.join(__dirname, '..', 'CHANGELOG.md');
    let changelog = '';
    
    if (fs.existsSync(changelogPath)) {
      changelog = fs.readFileSync(changelogPath, 'utf8');
    } else {
      changelog = '# Changelog\n\nAll notable changes to the CAM Protocol will be documented in this file.\n\n';
    }
    
    // Ask for release notes
    console.log('\nEnter release notes (end with a line containing only "END"):');
    let releaseNotes = '';
    
    await new Promise(resolve => {
      const onLine = line => {
        if (line === 'END') {
          rl.off('line', onLine);
          resolve();
        } else {
          releaseNotes += line + '\n';
        }
      };
      
      rl.on('line', onLine);
    });
    
    const date = new Date().toISOString().split('T')[0];
    const changelogEntry = `\n## [${newVersion}] - ${date}\n\n${releaseNotes}\n`;
    
    console.log(`\nChangelog entry to add:\n${changelogEntry}`);
    
    if (!isDryRun) {
      fs.writeFileSync(changelogPath, changelog.replace('# Changelog\n', `# Changelog\n${changelogEntry}`));
    }
    
    // Step 5: Commit changes
    console.log('\nCommitting changes...');
    if (!isDryRun) {
      execSync('git add package.json CHANGELOG.md', { stdio: 'inherit' });
      execSync(`git commit -m "chore: release v${newVersion}"`, { stdio: 'inherit' });
    }
    
    // Step 6: Create git tag
    console.log(`\nCreating git tag v${newVersion}...`);
    if (!isDryRun) {
      execSync(`git tag -a v${newVersion} -m "Version ${newVersion}"`, { stdio: 'inherit' });
    }
    
    // Step 7: Push changes and tag
    console.log('\nPushing changes and tag...');
    if (!isDryRun) {
      execSync('git push', { stdio: 'inherit' });
      execSync('git push --tags', { stdio: 'inherit' });
    }
    
    console.log(`\n${isDryRun ? '[DRY RUN] ' : ''}Release v${newVersion} created successfully!`);
    
    // Step 8: Create GitHub release (optional)
    const createGithubRelease = await new Promise(resolve => {
      rl.question('\nDo you want to create a GitHub release? (y/n): ', resolve);
    });
    
    if (createGithubRelease.toLowerCase() === 'y') {
      console.log('\nTo create a GitHub release, go to:');
      console.log(`https://github.com/Complete-Arbitration-Mesh/CAM-PROTOCOL/releases/new?tag=v${newVersion}`);
      console.log('and paste the release notes there.');
    }
    
  } catch (error) {
    console.error('Error creating release:', error.message);
  } finally {
    rl.close();
  }
}

// Run the main function
createRelease();
