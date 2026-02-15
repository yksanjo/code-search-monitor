const axios = require('axios');
const cheerio = require('cheerio');
const { detectCredentials, scanForDomains } = require('./scanner');

const CODE_SEARCH_ENGINES = [
  {
    name: 'SearchCode',
    url: 'https://searchcode.com/?q=',
    type: 'html'
  },
  {
    name: 'CodeGrepper',
    url: 'https://www.codegrepper.com/search.php?q=',
    type: 'html'
  }
];

class Monitor {
  constructor(domains, options = {}) {
    this.domains = domains;
    this.interval = options.interval || 30 * 60 * 1000;
    this.verbose = options.verbose || false;
    this.once = options.once || false;
    this.isRunning = false;
    this.lastCheck = null;
    this.findings = [];
  }

  async start() {
    this.isRunning = true;
    console.log('🚀 Starting code search monitoring...\n');

    await this.check();

    if (this.once) {
      console.log('\n✅ Single scan completed');
      this.printSummary();
      return;
    }

    console.log(`\n⏳ Continuous monitoring active. Checking every ${this.interval / 60000} minutes...`);

    this.intervalId = setInterval(async () => {
      await this.check();
    }, this.interval);
  }

  stop() {
    this.isRunning = false;
    if (this.intervalId) {
      clearInterval(this.intervalId);
    }
  }

  async check() {
    this.lastCheck = new Date();
    console.log(`\n[${this.lastCheck.toISOString()}] Checking code search engines...`);

    let totalScanned = 0;
    let threatsFound = 0;

    for (const engine of CODE_SEARCH_ENGINES) {
      try {
        if (this.verbose) {
          console.log(`  📂 Checking ${engine.name}...`);
        }

        const results = await this.searchCode(engine);
        totalScanned += results.length;

        for (const result of results) {
          if (result.findings.length > 0) {
            threatsFound += result.findings.length;
            this.findings.push(...result.findings);
            this.alert(result.findings);
          }
        }
      } catch (error) {
        console.error(`  ❌ Error checking ${engine.name}: ${error.message}`);
      }
    }

    console.log(`  ✅ Scanned ${totalScanned} results, found ${threatsFound} potential leaks`);
  }

  async searchCode(engine) {
    const results = [];

    for (const domain of this.domains) {
      try {
        const url = engine.url + encodeURIComponent(domain);
        const response = await axios.get(url, {
          timeout: 10000,
          headers: {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
          }
        });

        const $ = cheerio.load(response.data);
        const content = $('body').text();

        const domainMatches = scanForDomains(content, [domain]);
        if (domainMatches.length > 0) {
          const credentials = detectCredentials(content);
          if (credentials.length > 0) {
            results.push({
              domain: domain,
              engine: engine.name,
              findings: [{
                timestamp: new Date().toISOString(),
                source: engine.name,
                url: url,
                matchedDomains: domainMatches,
                credentials: credentials,
                snippet: content.substring(0, 200)
              }]
            });
          }
        }
      } catch (error) {
        if (this.verbose) {
          console.error(`    Error: ${error.message}`);
        }
      }
    }

    return results;
  }

  alert(findings) {
    for (const finding of findings) {
      console.log('\n🚨 ALERT: Potential Credential Leak Detected!');
      console.log('='.repeat(50));
      console.log(`Source: ${finding.source}`);
      console.log(`URL: ${finding.url}`);
      console.log(`Matched Domains: ${finding.matchedDomains.join(', ')}`);
      console.log(`Credential Types: ${finding.credentials.join(', ')}`);
      console.log('='.repeat(50));
    }
  }

  printSummary() {
    console.log('\n📊 Summary');
    console.log('='.repeat(30));
    console.log(`Total findings: ${this.findings.length}`);
  }
}

module.exports = Monitor;
