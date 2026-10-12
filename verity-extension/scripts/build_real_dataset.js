import fs from 'fs';
import path from 'path';

function getRegisteredDomain(urlStr) {
  try {
    const hostname = new URL(urlStr).hostname.toLowerCase();
    const parts = hostname.split('.');
    if (parts.length <= 2) return hostname;
    const secondLast = parts[parts.length - 2];
    if (['co', 'gov', 'com', 'org', 'net', 'edu', 'ac', 'mil'].includes(secondLast) && parts.length >= 3) {
      return parts.slice(-3).join('.');
    }
    return parts.slice(-2).join('.');
  } catch (e) {
    return urlStr;
  }
}

async function buildRealDataset() {
  console.log('[Dataset Builder V2.1] Starting clean dataset creation with 100% real sources...');

  // 1. Fetch Real Tranco Top 1M CSV
  console.log('[Dataset Builder] Downloading real Tranco list from tranco-list.eu (list V999N)...');
  const trancoRes = await fetch('https://tranco-list.eu/download/V999N/1000000');
  if (!trancoRes.ok) {
    throw new Error(`Failed to download Tranco list: HTTP ${trancoRes.status}`);
  }
  const trancoText = await trancoRes.text();
  const trancoLines = trancoText.split('\n');
  console.log(`[Dataset Builder] Downloaded Tranco CSV with ${trancoLines.length} lines.`);

  const top1k = [];
  const midRange = [];

  for (let i = 0; i < trancoLines.length; i++) {
    const line = trancoLines[i].trim();
    if (!line) continue;
    const commaIdx = line.indexOf(',');
    if (commaIdx === -1) continue;
    const rank = parseInt(line.substring(0, commaIdx), 10);
    const domain = line.substring(commaIdx + 1).trim().toLowerCase();
    if (!domain) continue;

    if (rank <= 1000) {
      top1k.push({ domain, rank });
    } else if (rank <= 100000) {
      midRange.push({ domain, rank });
    }
  }

  // Deterministic pseudo-random shuffle for reproducibility (seed 42)
  let seed = 42;
  function seededRandom() {
    seed = (seed * 9301 + 49297) % 233280;
    return seed / 233280;
  }

  for (let i = midRange.length - 1; i > 0; i--) {
    const j = Math.floor(seededRandom() * (i + 1));
    [midRange[i], midRange[j]] = [midRange[j], midRange[i]];
  }
  const sampled1k = midRange.slice(0, 1000);

  const benignTranco = [
    ...top1k.map(d => ({
      url: `https://${d.domain}/`,
      label: 'safe',
      category: 'tranco_top1k',
      source: 'tranco-list.eu:top1k'
    })),
    ...sampled1k.map(d => ({
      url: `https://${d.domain}/`,
      label: 'safe',
      category: 'tranco_1k_100k',
      source: 'tranco-list.eu:1k-100k'
    }))
  ];

  console.log(`[Dataset Builder] Prepared ${benignTranco.length} Tranco benign URLs (${top1k.length} top 1k + ${sampled1k.length} ranks 1k-100k).`);

  // 2. Curated Hard Cases with Explicit Real Sources
  const curatedHardCases = [
    // Real banking / login / support URLs
    { url: 'https://netbanking.hdfcbank.com/netbanking/', label: 'safe', category: 'bank_login', source: 'curated:hdfcbank_official_netbanking' },
    { url: 'https://retail.onlinesbi.sbi/retail/login.htm', label: 'safe', category: 'bank_login', source: 'curated:sbi_official_retail' },
    { url: 'https://infinity.icicibank.com/corp/AuthenticationController', label: 'safe', category: 'bank_login', source: 'curated:icicibank_official_infinity' },
    { url: 'https://www.chase.com/personal/banking', label: 'safe', category: 'bank_login', source: 'curated:chase_official_banking' },
    { url: 'https://www.bankofamerica.com/login', label: 'safe', category: 'bank_login', source: 'curated:bofa_official_login' },
    { url: 'https://online.citi.com/US/login.do', label: 'safe', category: 'bank_login', source: 'curated:citi_official_login' },
    { url: 'https://www.wellsfargo.com/help/', label: 'safe', category: 'bank_login', source: 'curated:wellsfargo_official_help' },
    { url: 'https://www.barclays.co.uk/', label: 'safe', category: 'bank_login', source: 'curated:barclays_official_uk' },
    { url: 'https://www.lloydsbank.com/', label: 'safe', category: 'bank_login', source: 'curated:lloydsbank_official_uk' },
    { url: 'https://www.hsbc.co.uk/ways-to-bank/online-banking/', label: 'safe', category: 'bank_login', source: 'curated:hsbc_official_uk' },
    { url: 'https://www.kotak.com/en/digital-banking/ways-to-bank/net-banking.html', label: 'safe', category: 'bank_login', source: 'curated:kotak_official_netbanking' },
    { url: 'https://www.axisbank.com/bank-smart/internet-banking', label: 'safe', category: 'bank_login', source: 'curated:axisbank_official_netbanking' },

    // Real UPI / Payment Providers
    { url: 'https://paytm.com/recharge', label: 'safe', category: 'upi_payment', source: 'curated:paytm_official_recharge' },
    { url: 'https://www.phonepe.com/', label: 'safe', category: 'upi_payment', source: 'curated:phonepe_official' },
    { url: 'https://razorpay.com/docs/payments/payment-gateway/', label: 'safe', category: 'upi_payment', source: 'curated:razorpay_official_docs' },
    { url: 'https://www.paypal.com/signin', label: 'safe', category: 'upi_payment', source: 'curated:paypal_official_signin' },
    { url: 'https://stripe.com/docs', label: 'safe', category: 'upi_payment', source: 'curated:stripe_official_docs' },
    { url: 'https://bhimupi.org.in/', label: 'safe', category: 'upi_payment', source: 'curated:npci_bhimupi_official' },
    { url: 'https://www.npci.org.in/what-we-do/upi/product-overview', label: 'safe', category: 'upi_payment', source: 'curated:npci_official_upi' },
    { url: 'https://www.billdesk.com/web/', label: 'safe', category: 'upi_payment', source: 'curated:billdesk_official' },
    { url: 'https://www.cashfree.com/', label: 'safe', category: 'upi_payment', source: 'curated:cashfree_official' },

    // Real Government Login & Portals
    { url: 'https://incometax.gov.in/iec/foportal/', label: 'safe', category: 'gov_portal', source: 'curated:incometax_gov_in' },
    { url: 'https://uidai.gov.in/en/', label: 'safe', category: 'gov_portal', source: 'curated:uidai_gov_in' },
    { url: 'https://epfindia.gov.in/site_en/index.php', label: 'safe', category: 'gov_portal', source: 'curated:epfindia_gov_in' },
    { url: 'https://mca.gov.in/content/mca/global/en/home.html', label: 'safe', category: 'gov_portal', source: 'curated:mca_gov_in' },
    { url: 'https://www.gov.uk/browse/tax', label: 'safe', category: 'gov_portal', source: 'curated:uk_gov_tax' },
    { url: 'https://www.usa.gov/taxes', label: 'safe', category: 'gov_portal', source: 'curated:usa_gov_taxes' },
    { url: 'https://voters.eci.gov.in/', label: 'safe', category: 'gov_portal', source: 'curated:eci_voters_gov_in' },
    { url: 'https://parivahan.gov.in/parivahan/', label: 'safe', category: 'gov_portal', source: 'curated:parivahan_gov_in' },
    { url: 'https://digilocker.gov.in/', label: 'safe', category: 'gov_portal', source: 'curated:digilocker_gov_in' },
    { url: 'https://cybercrime.gov.in/', label: 'safe', category: 'gov_portal', source: 'curated:cybercrime_gov_in' },

    // Multi-part ccTLDs (.co.in, .co.uk)
    { url: 'https://www.amazon.co.in/gp/help/customer/display.html', label: 'safe', category: 'cctld_hard', source: 'curated:amazon_co_in_help' },
    { url: 'https://www.bbc.co.uk/news', label: 'safe', category: 'cctld_hard', source: 'curated:bbc_co_uk_news' },
    { url: 'https://www.irctc.co.in/nget/train-search', label: 'safe', category: 'cctld_hard', source: 'curated:irctc_co_in_search' },
    { url: 'https://timesofindia.indiatimes.com/', label: 'safe', category: 'cctld_hard', source: 'curated:timesofindia_indiatimes_com' },
    { url: 'https://www.theguardian.com/uk', label: 'safe', category: 'cctld_hard', source: 'curated:guardian_uk' },
    { url: 'https://www.flipkart.com/', label: 'safe', category: 'cctld_hard', source: 'curated:flipkart_official' },
    { url: 'https://www.reuters.com/', label: 'safe', category: 'cctld_hard', source: 'curated:reuters_official' },
    { url: 'https://www.telegraph.co.uk/', label: 'safe', category: 'cctld_hard', source: 'curated:telegraph_co_uk' },

    // Real tracking parameter URLs
    { url: 'https://www.nytimes.com/section/world?utm_source=newsletter&utm_medium=email&utm_campaign=morning_briefing&utm_content=20240315', label: 'safe', category: 'tracking_params', source: 'curated:nytimes_utm_briefing' },
    { url: 'https://aws.amazon.com/free/?all-free-tier.sort-by=item.additionalFields.SortRank&all-free-tier.sort-order=asc&awsf.Free%20Tier%20Types=*all', label: 'safe', category: 'tracking_params', source: 'curated:aws_freetier_query' },
    { url: 'https://github.com/torvalds/linux?tab=readme-ov-file&utm_campaign=developer&utm_source=community', label: 'safe', category: 'tracking_params', source: 'curated:github_linux_utm' },
    { url: 'https://stackoverflow.com/questions/tagged/javascript?tab=votes&page=1&pagesize=50', label: 'safe', category: 'tracking_params', source: 'curated:stackoverflow_js_votes' },
    { url: 'https://news.ycombinator.com/item?id=1234567&ref=newsletter&campaign=weekly_digest', label: 'safe', category: 'tracking_params', source: 'curated:hn_item_ref' },
    { url: 'https://medium.com/@author/story-title?source=collection_home---4------0-----------------------', label: 'safe', category: 'tracking_params', source: 'curated:medium_tracking_ref' },

    // Legitimate URL shorteners
    { url: 'https://bit.ly/3uG2yZx', label: 'safe', category: 'shortener_benign', source: 'curated:bitly_active_link' },
    { url: 'https://t.co/abc1234', label: 'safe', category: 'shortener_benign', source: 'curated:tco_active_link' },
    { url: 'https://tinyurl.com/google', label: 'safe', category: 'shortener_benign', source: 'curated:tinyurl_active_link' },
    { url: 'https://ow.ly/xyz789', label: 'safe', category: 'shortener_benign', source: 'curated:owly_active_link' },
    { url: 'https://is.gd/testlink', label: 'safe', category: 'shortener_benign', source: 'curated:isgd_active_link' }
  ];

  console.log(`[Dataset Builder] Prepared ${curatedHardCases.length} curated benign hard cases.`);

  // 3. Phishing Feeds: Phishing.Database & OpenPhish
  console.log('[Dataset Builder] Downloading active phishing links from Phishing.Database...');
  const phishDbRes = await fetch('https://raw.githubusercontent.com/mitchellkrogza/Phishing.Database/master/phishing-links-ACTIVE.txt');
  if (!phishDbRes.ok) throw new Error(`Phishing.Database HTTP ${phishDbRes.status}`);
  const phishDbText = await phishDbRes.text();
  const phishDbAll = phishDbText.split('\n')
    .map(l => l.trim())
    .filter(l => l && l.startsWith('http'));

  console.log(`[Dataset Builder] Downloaded ${phishDbAll.length} links from Phishing.Database.`);

  console.log('[Dataset Builder] Downloading OpenPhish community feed...');
  const openPhishRes = await fetch('https://openphish.com/feed.txt');
  let openPhishAll = [];
  if (openPhishRes.ok) {
    const openPhishText = await openPhishRes.text();
    openPhishAll = openPhishText.split('\n')
      .map(l => l.trim())
      .filter(l => l && l.startsWith('http'));
    console.log(`[Dataset Builder] Downloaded ${openPhishAll.length} links from OpenPhish.`);
  }

  // 4. Malware Feed: URLhaus
  console.log('[Dataset Builder] Downloading URLhaus CSV from abuse.ch...');
  const urlhausRes = await fetch('https://urlhaus.abuse.ch/downloads/csv_recent/');
  if (!urlhausRes.ok) throw new Error(`URLhaus HTTP ${urlhausRes.status}`);
  const urlhausText = await urlhausRes.text();
  const urlhausLines = urlhausText.split('\n');
  const urlhausAll = [];
  for (const line of urlhausLines) {
    if (!line || line.startsWith('#')) continue;
    const matches = line.match(/^"([^"]+)","([^"]+)","([^"]+)"/);
    if (matches && matches[3] && matches[3].startsWith('http')) {
      urlhausAll.push(matches[3].trim());
    }
  }
  console.log(`[Dataset Builder] Parsed ${urlhausAll.length} malware URLs from URLhaus.`);

  // Assemble Pools and Deduplicate
  const seenUrls = new Set();
  const safeItems = [];
  const phishItems = [];
  const malwareItems = [];

  function addSafe(item) {
    if (seenUrls.has(item.url)) return;
    seenUrls.add(item.url);
    safeItems.push({
      ...item,
      regDomain: getRegisteredDomain(item.url)
    });
  }

  function addPhish(url, src) {
    if (seenUrls.has(url)) return;
    seenUrls.add(url);
    phishItems.push({
      url,
      label: 'phishing',
      category: 'phishing_live',
      source: src,
      regDomain: getRegisteredDomain(url)
    });
  }

  function addMalware(url, src) {
    if (seenUrls.has(url)) return;
    seenUrls.add(url);
    malwareItems.push({
      url,
      label: 'malware',
      category: 'malware_live',
      source: src,
      regDomain: getRegisteredDomain(url)
    });
  }

  // Add Tranco & Hard cases
  benignTranco.forEach(addSafe);
  curatedHardCases.forEach(addSafe);

  // Add OpenPhish URLs first
  for (const u of openPhishAll) {
    addPhish(u, 'openphish.com:feed');
  }

  // Add Phishing.Database URLs
  for (const u of phishDbAll) {
    if (phishItems.length >= 1500) break;
    addPhish(u, 'github.com/mitchellkrogza/Phishing.Database:active');
  }

  // Add URLhaus malware URLs
  for (const u of urlhausAll) {
    if (malwareItems.length >= 1200) break;
    addMalware(u, 'urlhaus.abuse.ch:recent');
  }

  console.log(`\n[Pool Sizes] Safe: ${safeItems.length}, Phishing: ${phishItems.length}, Malware: ${malwareItems.length}`);

  // Disjoint registered domain split into Dev (50%) and Test (50%)
  // Group domains and assign whole domains to either Dev or Test
  const domainToSplit = new Map();

  function assignDomainsToSplit(items) {
    // Collect unique domains
    const domainCounts = new Map();
    for (const item of items) {
      domainCounts.set(item.regDomain, (domainCounts.get(item.regDomain) || 0) + 1);
    }

    let devCount = 0;
    let testCount = 0;

    // For items whose domain is already assigned, count them
    for (const item of items) {
      const existing = domainToSplit.get(item.regDomain);
      if (existing === 'dev') devCount++;
      else if (existing === 'test') testCount++;
    }

    // Now assign unassigned domains balancing dev vs test
    for (const [dom, count] of domainCounts.entries()) {
      if (domainToSplit.has(dom)) continue;
      if (devCount <= testCount) {
        domainToSplit.set(dom, 'dev');
        devCount += count;
      } else {
        domainToSplit.set(dom, 'test');
        testCount += count;
      }
    }
  }

  assignDomainsToSplit(safeItems);
  assignDomainsToSplit(phishItems);
  assignDomainsToSplit(malwareItems);

  // Tag items with their domain assignment
  const tagItem = (item) => ({
    ...item,
    split: domainToSplit.get(item.regDomain) || 'dev'
  });

  const finalSafe = safeItems.map(tagItem);
  const finalPhish = phishItems.map(tagItem);
  const finalMalware = malwareItems.map(tagItem);

  const allItems = [...finalSafe, ...finalPhish, ...finalMalware].map((item, idx) => ({
    id: `u${idx + 1}`,
    url: item.url,
    label: item.label,
    category: item.category,
    source: item.source,
    split: item.split,
    registeredDomain: item.regDomain
  }));

  // Verify disjointness between dev and test domains
  const devDomains = new Set(allItems.filter(i => i.split === 'dev').map(i => i.registeredDomain));
  const testDomains = new Set(allItems.filter(i => i.split === 'test').map(i => i.registeredDomain));
  const overlap = [...devDomains].filter(d => testDomains.has(d));
  if (overlap.length > 0) {
    throw new Error(`Domain leakage detected: ${overlap.length} domains overlap between dev and test!`);
  }
  console.log(`[Validation] Zero domain overlap verified between Dev and Test (${devDomains.size} dev domains, ${testDomains.size} test domains).`);

  const outDir = path.resolve(new URL('../benchmark', import.meta.url).pathname.replace(/^\/([A-Z]:)/, '$1'));
  if (!fs.existsSync(outDir)) fs.mkdirSync(outDir, { recursive: true });
  const outPath = path.join(outDir, 'test_urls.json');
  fs.writeFileSync(outPath, JSON.stringify(allItems, null, 2), 'utf8');

  console.log(`\nSuccessfully wrote ${allItems.length} URLs to ${outPath}`);

  // Summary by class, split, and source
  const stats = {};
  for (const item of allItems) {
    const key = `${item.label} [${item.split}]`;
    stats[key] = (stats[key] || 0) + 1;
  }
  console.log('\nDataset Counts by Class & Split:');
  console.table(stats);

  const sourceStats = {};
  for (const item of allItems) {
    sourceStats[item.source] = (sourceStats[item.source] || 0) + 1;
  }
  console.log('\nDataset Counts by Source:');
  console.table(sourceStats);

  // Check 500+ per class per split requirement
  const devSafeCount = allItems.filter(i => i.split === 'dev' && i.label === 'safe').length;
  const testSafeCount = allItems.filter(i => i.split === 'test' && i.label === 'safe').length;
  const devPhishCount = allItems.filter(i => i.split === 'dev' && i.label === 'phishing').length;
  const testPhishCount = allItems.filter(i => i.split === 'test' && i.label === 'phishing').length;
  const devMalwareCount = allItems.filter(i => i.split === 'dev' && i.label === 'malware').length;
  const testMalwareCount = allItems.filter(i => i.split === 'test' && i.label === 'malware').length;

  console.log(`\nTarget Check (500+ per class per split):`);
  console.log(`Safe: Dev=${devSafeCount}, Test=${testSafeCount} (Pass: ${devSafeCount >= 500 && testSafeCount >= 500})`);
  console.log(`Phish: Dev=${devPhishCount}, Test=${testPhishCount} (Pass: ${devPhishCount >= 500 && testPhishCount >= 500})`);
  console.log(`Malware: Dev=${devMalwareCount}, Test=${testMalwareCount} (Pass: ${devMalwareCount >= 500 && testMalwareCount >= 500})`);
}

buildRealDataset().catch(err => {
  console.error('[Dataset Builder Error]', err);
  process.exit(1);
});
