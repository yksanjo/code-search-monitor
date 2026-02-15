#!/usr/bin/env node

const { Command } = require('commander');
const Monitor = require('./monitor');
const { loadConfig, validateDomains } = require('./config');

const program = new Command();

program
  .name('code-search-monitor')
  .description('Monitor code search engines for leaked credentials')
  .version('1.0.0')
  .option('-c, --config <path>', 'Path to config file', 'config.json')
  .option('-d, --domains <domains>', 'Comma-separated list of domains to monitor')
  .option('-o, --once', 'Run once and exit')
  .option('-i, --interval <minutes>', 'Check interval in minutes', '30')
  .option('-v, --verbose', 'Verbose output')
  .parse(process.argv);

const options = program.opts();

async function main() {
  console.log('🔍 Code Search Monitor');
  console.log('==========================\n');

  const config = loadConfig(options.config);
  
  let domains = [];
  if (options.domains) {
    domains = options.domains.split(',').map(d => d.trim());
  } else if (config.domains) {
    domains = config.domains;
  } else {
    console.error('Error: No domains specified. Use -d option or config.json');
    process.exit(1);
  }

  const validDomains = validateDomains(domains);
  if (validDomains.length === 0) {
    console.error('Error: No valid domains provided');
    process.exit(1);
  }

  console.log(`Monitoring ${validDomains.length} domain(s): ${validDomains.join(', ')}`);
  console.log(`Mode: ${options.once ? 'Single scan' : 'Continuous monitoring'}\n`);

  const monitor = new Monitor(validDomains, {
    interval: parseInt(options.interval) * 60 * 1000,
    verbose: options.verbose,
    once: options.once
  });

  try {
    await monitor.start();
  } catch (error) {
    console.error('Error:', error.message);
    process.exit(1);
  }
}

main();
