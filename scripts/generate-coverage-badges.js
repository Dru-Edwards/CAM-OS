/**
 * Script to generate coverage badges from Vitest coverage reports
 */
const fs = require('fs');
const path = require('path');

// Create badges directory if it doesn't exist
const badgesDir = path.join(__dirname, '..', 'badges');
if (!fs.existsSync(badgesDir)) {
  fs.mkdirSync(badgesDir);
}

// Read the coverage summary JSON file
const coverageSummaryPath = path.join(__dirname, '..', 'coverage', 'coverage-summary.json');
if (!fs.existsSync(coverageSummaryPath)) {
  console.error('Coverage summary file not found. Run vitest with coverage first.');
  process.exit(1);
}

try {
  const coverageSummary = JSON.parse(fs.readFileSync(coverageSummaryPath, 'utf8'));
  const total = coverageSummary.total;

  // Generate badges for each metric
  const metrics = {
    statements: Math.floor(total.statements.pct),
    branches: Math.floor(total.branches.pct),
    functions: Math.floor(total.functions.pct),
    lines: Math.floor(total.lines.pct)
  };

  // Write badge data files
  Object.entries(metrics).forEach(([metric, value]) => {
    const badgeContent = value.toString();
    fs.writeFileSync(path.join(badgesDir, `${metric}.svg`), generateBadgeSvg(metric, badgeContent));
  });

  console.log('Coverage badges generated successfully!');
} catch (error) {
  console.error('Error generating coverage badges:', error);
  process.exit(1);
}

/**
 * Generate a simple SVG badge
 */
function generateBadgeSvg(label, value) {
  // Determine color based on coverage percentage
  const percentage = parseInt(value, 10);
  let color = '#4c1';  // Green for high coverage
  if (percentage < 80) color = '#dfb317';  // Yellow for medium coverage
  if (percentage < 60) color = '#e05d44';  // Red for low coverage

  return `<svg xmlns="http://www.w3.org/2000/svg" width="100" height="20">
  <linearGradient id="b" x2="0" y2="100%">
    <stop offset="0" stop-color="#bbb" stop-opacity=".1"/>
    <stop offset="1" stop-opacity=".1"/>
  </linearGradient>
  <mask id="a">
    <rect width="100" height="20" rx="3" fill="#fff"/>
  </mask>
  <g mask="url(#a)">
    <path fill="#555" d="M0 0h70v20H0z"/>
    <path fill="${color}" d="M70 0h30v20H70z"/>
    <path fill="url(#b)" d="M0 0h100v20H0z"/>
  </g>
  <g fill="#fff" text-anchor="middle" font-family="DejaVu Sans,Verdana,Geneva,sans-serif" font-size="11">
    <text x="35" y="15" fill="#010101" fill-opacity=".3">${label}</text>
    <text x="35" y="14">${label}</text>
    <text x="85" y="15" fill="#010101" fill-opacity=".3">${value}%</text>
    <text x="85" y="14">${value}%</text>
  </g>
</svg>`;
}
