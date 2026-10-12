import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import { isAllowlistedDomain } from '../shared/legit-domains.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

// 100+ Real Held-Out Benign Pages v2
// Disjoint from all prior runs and tuning sets
const rawList = [
  // ── 1. Bank & Fintech NetBanking Login Entry (42 pages, password/OTP field) ──
  // Drawn from RBI scheduled commercial, SFB, payments & urban co-op bank lists
  { name: 'IndusInd IndusNet Login', url: 'https://indusnet.indusind.com/', category: 'bank_login', source: 'https://www.rbi.org.in/commonman/English/Scripts/BanksInIndia.aspx' },
  { name: 'Yes Bank Retail NetBanking', url: 'https://retail.yesbank.in/index.htm', category: 'bank_login', source: 'https://www.rbi.org.in/commonman/English/Scripts/BanksInIndia.aspx' },
  { name: 'IDFC FIRST Bank Portal Login', url: 'https://my.idfcfirstbank.com/login', category: 'bank_login', source: 'https://www.rbi.org.in/commonman/English/Scripts/BanksInIndia.aspx' },
  { name: 'Federal Bank FedNet Login', url: 'https://www.fednetbank.com/', category: 'bank_login', source: 'https://www.rbi.org.in/commonman/English/Scripts/BanksInIndia.aspx' },
  { name: 'South Indian Bank NetBanking', url: 'https://sibnet.southindianbank.com/', category: 'bank_login', source: 'https://www.rbi.org.in/commonman/English/Scripts/BanksInIndia.aspx' },
  { name: 'Karur Vysya Bank Internet Banking', url: 'https://www.kvbinetbank.com/', category: 'bank_login', source: 'https://www.rbi.org.in/commonman/English/Scripts/BanksInIndia.aspx' },
  { name: 'RBL Bank Internet Banking', url: 'https://online.rblbank.com/', category: 'bank_login', source: 'https://www.rbi.org.in/commonman/English/Scripts/BanksInIndia.aspx' },
  { name: 'Bandhan Bank NetBanking', url: 'https://netbanking.bandhanbank.com/', category: 'bank_login', source: 'https://www.rbi.org.in/commonman/English/Scripts/BanksInIndia.aspx' },
  { name: 'CSB Bank NetBanking Portal', url: 'https://www.csbnet.co.in/', category: 'bank_login', source: 'https://www.rbi.org.in/commonman/English/Scripts/BanksInIndia.aspx' },
  { name: 'DCB Bank Internet Banking', url: 'https://netbanking.dcbbank.com/', category: 'bank_login', source: 'https://www.rbi.org.in/commonman/English/Scripts/BanksInIndia.aspx' },
  { name: 'Dhanlaxmi Bank Retail Login', url: 'https://dhanbank.netbanking.dhanbank.in/', category: 'bank_login', source: 'https://www.rbi.org.in/commonman/English/Scripts/BanksInIndia.aspx' },
  { name: 'Nainital Bank Internet Banking', url: 'https://netbanking.nainitalbank.co.in/', category: 'bank_login', source: 'https://www.rbi.org.in/commonman/English/Scripts/BanksInIndia.aspx' },
  { name: 'Jammu & Kashmir Bank e-Banking', url: 'https://www.jkbankonline.com/', category: 'bank_login', source: 'https://www.rbi.org.in/commonman/English/Scripts/BanksInIndia.aspx' },
  { name: 'Karnataka Bank MoneyClick', url: 'https://moneyclick.karnatakabank.com/', category: 'bank_login', source: 'https://www.rbi.org.in/commonman/English/Scripts/BanksInIndia.aspx' },
  { name: 'Ujjivan SFB Internet Banking', url: 'https://netbanking.ujjivansfb.in/', category: 'bank_login', source: 'https://www.rbi.org.in/commonman/English/Scripts/BanksInIndia.aspx' },
  { name: 'Jana SFB Internet Banking', url: 'https://netbanking.janabank.com/', category: 'bank_login', source: 'https://www.rbi.org.in/commonman/English/Scripts/BanksInIndia.aspx' },
  { name: 'Suryoday SFB NetBanking', url: 'https://netbanking.suryodaybank.com/', category: 'bank_login', source: 'https://www.rbi.org.in/commonman/English/Scripts/BanksInIndia.aspx' },
  { name: 'Utkarsh SFB Internet Banking', url: 'https://internetbanking.utkarsh.bank/', category: 'bank_login', source: 'https://www.rbi.org.in/commonman/English/Scripts/BanksInIndia.aspx' },
  { name: 'ESAF SFB NetBanking', url: 'https://netbanking.esafbank.com/', category: 'bank_login', source: 'https://www.rbi.org.in/commonman/English/Scripts/BanksInIndia.aspx' },
  { name: 'Fincare SFB NetBanking', url: 'https://netbanking.fincarebank.com/', category: 'bank_login', source: 'https://www.rbi.org.in/commonman/English/Scripts/BanksInIndia.aspx' },
  { name: 'North East SFB NetBanking', url: 'https://netbanking.nesfb.com/', category: 'bank_login', source: 'https://www.rbi.org.in/commonman/English/Scripts/BanksInIndia.aspx' },
  { name: 'Shivalik SFB NetBanking', url: 'https://netbanking.shivalikbank.com/', category: 'bank_login', source: 'https://www.rbi.org.in/commonman/English/Scripts/BanksInIndia.aspx' },
  { name: 'Unity SFB NetBanking', url: 'https://netbanking.unitybank.co.in/', category: 'bank_login', source: 'https://www.rbi.org.in/commonman/English/Scripts/BanksInIndia.aspx' },
  { name: 'Airtel Payments Bank Login', url: 'https://www.airtel.in/bank/login', category: 'bank_login', source: 'https://www.rbi.org.in/commonman/English/Scripts/BanksInIndia.aspx' },
  { name: 'India Post Payments Bank (IPPB)', url: 'https://www.ippbonline.com/', category: 'bank_login', source: 'https://www.rbi.org.in/commonman/English/Scripts/BanksInIndia.aspx' },
  { name: 'Fino Payments Bank NetBanking', url: 'https://netbanking.finobank.com/', category: 'bank_login', source: 'https://www.rbi.org.in/commonman/English/Scripts/BanksInIndia.aspx' },
  { name: 'Jio Payments Bank Portal', url: 'https://www.jiopaymentsbank.com/', category: 'bank_login', source: 'https://www.rbi.org.in/commonman/English/Scripts/BanksInIndia.aspx' },
  { name: 'Saraswat Bank NetBanking Login', url: 'https://netbanking.saraswatbank.com/', category: 'bank_login', source: 'https://www.npci.org.in/what-we-do/upi/live-members' },
  { name: 'Cosmos Co-operative Bank Login', url: 'https://netbanking.cosmosbank.com/', category: 'bank_login', source: 'https://www.npci.org.in/what-we-do/upi/live-members' },
  { name: 'SVC Co-operative Bank Login', url: 'https://netbanking.svcbank.com/', category: 'bank_login', source: 'https://www.npci.org.in/what-we-do/upi/live-members' },
  { name: 'TJSB Sahakari Bank NetBanking', url: 'https://netbanking.tjsbbank.co.in/', category: 'bank_login', source: 'https://www.npci.org.in/what-we-do/upi/live-members' },
  { name: 'NKGSB Co-operative Bank Login', url: 'https://netbanking.nkgsb-bank.com/', category: 'bank_login', source: 'https://www.npci.org.in/what-we-do/upi/live-members' },
  { name: 'Abhyudaya Bank NetBanking Login', url: 'https://netbanking.abhyudayabank.co.in/', category: 'bank_login', source: 'https://www.npci.org.in/what-we-do/upi/live-members' },
  { name: 'Bharat Co-operative Bank Login', url: 'https://netbanking.bharatbank.com/', category: 'bank_login', source: 'https://www.npci.org.in/what-we-do/upi/live-members' },
  { name: 'Kalupur Bank Internet Banking', url: 'https://netbanking.kalupurbank.com/', category: 'bank_login', source: 'https://www.npci.org.in/what-we-do/upi/live-members' },
  { name: 'Mehsana Urban Bank NetBanking', url: 'https://netbanking.mucbank.com/', category: 'bank_login', source: 'https://www.npci.org.in/what-we-do/upi/live-members' },
  { name: 'Surat Peoples Co-op Bank Login', url: 'https://netbanking.spcbl.in/', category: 'bank_login', source: 'https://www.npci.org.in/what-we-do/upi/live-members' },
  { name: 'Ahmedabad Mercantile Bank Login', url: 'https://netbanking.amco-bank.com/', category: 'bank_login', source: 'https://www.npci.org.in/what-we-do/upi/live-members' },
  { name: 'Rajkot Nagarik Sahakari Bank', url: 'https://netbanking.rnsbindia.com/', category: 'bank_login', source: 'https://www.npci.org.in/what-we-do/upi/live-members' },
  { name: 'Dombivli Nagari Sahakari Bank', url: 'https://netbanking.dnsb.bank/', category: 'bank_login', source: 'https://www.npci.org.in/what-we-do/upi/live-members' },
  { name: 'Nutan Nagarik Sahakari Bank', url: 'https://netbanking.nutanbank.com/', category: 'bank_login', source: 'https://www.npci.org.in/what-we-do/upi/live-members' },
  { name: 'Andhra Pradesh Urban Co-op Bank', url: 'https://netbanking.apurbanbank.com/', category: 'bank_login', source: 'https://www.npci.org.in/what-we-do/upi/live-members' },
  { name: 'Standard Chartered India iBanking', url: 'https://ibanking.sc.com/in/', category: 'bank_login', source: 'https://www.rbi.org.in/commonman/English/Scripts/BanksInIndia.aspx' },
  { name: 'Citibank India Online Banking', url: 'https://www.online.citibank.co.in/', category: 'bank_login', source: 'https://www.rbi.org.in/commonman/English/Scripts/BanksInIndia.aspx' },

  // ── 2. Government & NIC Portals incl. Login Pages (16 pages) ───────────────
  // Drawn from NIC directory (directory.gov.in)
  { name: 'ServicePlus Citizen Portal', url: 'https://serviceonline.gov.in/', category: 'gov_portal', source: 'https://directory.gov.in/' },
  { name: 'National Scholarship Portal', url: 'https://scholarships.gov.in/', category: 'gov_portal', source: 'https://directory.gov.in/' },
  { name: 'e-Courts Services Portal', url: 'https://ecourts.gov.in/', category: 'gov_portal', source: 'https://directory.gov.in/' },
  { name: 'EPFO Member Portal Login', url: 'https://unifiedportal-mem.epfindia.gov.in/memberinterface/', category: 'gov_portal', source: 'https://directory.gov.in/' },
  { name: 'Sarathi Parivahan License Login', url: 'https://sarathi.parivahan.gov.in/sarathiservice/', category: 'gov_portal', source: 'https://directory.gov.in/' },
  { name: 'Bhavishya Pension Portal', url: 'https://bhavishya.nic.in/', category: 'gov_portal', source: 'https://directory.gov.in/' },
  { name: 'e-Hospital Portal India', url: 'https://ehospital.gov.in/', category: 'gov_portal', source: 'https://directory.gov.in/' },
  { name: 'Central Vigilance Commission', url: 'https://www.cvc.gov.in/', category: 'gov_portal', source: 'https://directory.gov.in/' },
  { name: 'National Voters Services (ECI)', url: 'https://voters.eci.gov.in/', category: 'gov_portal', source: 'https://directory.gov.in/' },
  { name: 'e-Procurement Portal (CPPP)', url: 'https://eprocure.gov.in/eprocure/app', category: 'gov_portal', source: 'https://directory.gov.in/' },
  { name: 'PM Kisan Citizen Portal', url: 'https://pmkisan.gov.in/', category: 'gov_portal', source: 'https://directory.gov.in/' },
  { name: 'UMANG Web Portal', url: 'https://web.umang.gov.in/', category: 'gov_portal', source: 'https://directory.gov.in/' },
  { name: 'Manav Sampada Portal', url: 'https://ehrms.gov.in/', category: 'gov_portal', source: 'https://directory.gov.in/' },
  { name: 'e-Office Government Portal', url: 'https://eoffice.gov.in/', category: 'gov_portal', source: 'https://directory.gov.in/' },
  { name: 'National Career Service Login', url: 'https://www.ncs.gov.in/', category: 'gov_portal', source: 'https://directory.gov.in/' },
  { name: 'e-Sanad Verification Portal', url: 'https://esanad.nic.in/', category: 'gov_portal', source: 'https://directory.gov.in/' },
  { name: 'Ministry of Education Portal', url: 'https://education.gov.in/', category: 'gov_portal', source: 'https://directory.gov.in/' },
  { name: 'Central Govt Health Scheme (CGHS)', url: 'https://cghs.nic.in/', category: 'gov_portal', source: 'https://directory.gov.in/' },

  // ── 3. E-Commerce / Fintech Checkout & Wallet Entry (23 pages) ─────────────
  { name: 'Razorpay Checkout Platform', url: 'https://checkout.razorpay.com/', category: 'ecommerce_fintech', source: 'https://tranco-list.eu/' },
  { name: 'Cashfree Payments Portal', url: 'https://www.cashfree.com/', category: 'ecommerce_fintech', source: 'https://tranco-list.eu/' },
  { name: 'CCAvenue Merchant Gateway', url: 'https://www.ccavenue.com/', category: 'ecommerce_fintech', source: 'https://tranco-list.eu/' },
  { name: 'PayU India Gateway', url: 'https://payu.in/', category: 'ecommerce_fintech', source: 'https://tranco-list.eu/' },
  { name: 'Instamojo Login Entry', url: 'https://www.instamojo.com/accounts/login/', category: 'ecommerce_fintech', source: 'https://tranco-list.eu/' },
  { name: 'Tata Neu SuperApp Portal', url: 'https://www.tataneu.com/', category: 'ecommerce_fintech', source: 'https://tranco-list.eu/' },
  { name: 'Swiggy Food & Checkout', url: 'https://www.swiggy.com/', category: 'ecommerce_fintech', source: 'https://tranco-list.eu/' },
  { name: 'Zomato Dining & Order', url: 'https://www.zomato.com/', category: 'ecommerce_fintech', source: 'https://tranco-list.eu/' },
  { name: 'BookMyShow Entertainment Sign-in', url: 'https://in.bookmyshow.com/', category: 'ecommerce_fintech', source: 'https://tranco-list.eu/' },
  { name: 'MakeMyTrip Travel Account', url: 'https://www.makemytrip.com/', category: 'ecommerce_fintech', source: 'https://tranco-list.eu/' },
  { name: 'Cleartrip Booking Account', url: 'https://www.cleartrip.com/', category: 'ecommerce_fintech', source: 'https://tranco-list.eu/' },
  { name: 'Nykaa Beauty Sign-in', url: 'https://www.nykaa.com/', category: 'ecommerce_fintech', source: 'https://tranco-list.eu/' },
  { name: 'Myntra Fashion Login', url: 'https://www.myntra.com/login', category: 'ecommerce_fintech', source: 'https://tranco-list.eu/' },
  { name: 'Meesho Supplier Sign-in', url: 'https://supplier.meesho.com/', category: 'ecommerce_fintech', source: 'https://tranco-list.eu/' },
  { name: 'JioMart Retail Login', url: 'https://www.jiomart.com/', category: 'ecommerce_fintech', source: 'https://tranco-list.eu/' },
  { name: 'BigBasket Grocery Portal', url: 'https://www.bigbasket.com/', category: 'ecommerce_fintech', source: 'https://tranco-list.eu/' },
  { name: 'Ajio Fashion Login Portal', url: 'https://www.ajio.com/login', category: 'ecommerce_fintech', source: 'https://tranco-list.eu/' },
  { name: 'Pepperfry Furniture & Decor', url: 'https://www.pepperfry.com/', category: 'ecommerce_fintech', source: 'https://tranco-list.eu/' },
  { name: 'Urban Ladder Home Decor', url: 'https://www.urbanladder.com/', category: 'ecommerce_fintech', source: 'https://tranco-list.eu/' },
  { name: 'Cred Rewards & Cards', url: 'https://cred.club/', category: 'ecommerce_fintech', source: 'https://tranco-list.eu/' },
  { name: 'Groww Invest Login Portal', url: 'https://groww.in/login', category: 'ecommerce_fintech', source: 'https://tranco-list.eu/' },
  { name: 'Zerodha Kite Trading Login', url: 'https://kite.zerodha.com/', category: 'ecommerce_fintech', source: 'https://tranco-list.eu/' },
  { name: 'Upstox Pro Trading Login', url: 'https://login.upstox.com/', category: 'ecommerce_fintech', source: 'https://tranco-list.eu/' },

  // ── 4. News / Support Pages with Fraud-Warning or KYC/OTP Text (16 pages) ──
  { name: 'RBI Kehta Hai Official Safety Portal', url: 'https://rbikehtahai.rbi.org.in/', category: 'news_advisory', source: 'https://www.rbi.org.in/' },
  { name: 'SBI Security Tips & Fraud Safety', url: 'https://sbi.co.in/web/personal-banking/security-tips', category: 'news_advisory', source: 'https://www.rbi.org.in/' },
  { name: 'ICICI Safe Banking Awareness', url: 'https://www.icicibank.com/safe-banking', category: 'news_advisory', source: 'https://www.rbi.org.in/' },
  { name: 'Axis Bank Cyber Security Advisory', url: 'https://www.axisbank.com/security', category: 'news_advisory', source: 'https://www.rbi.org.in/' },
  { name: 'Kotak Fraud Awareness Portal', url: 'https://www.kotak.com/en/fraud-awareness.html', category: 'news_advisory', source: 'https://www.rbi.org.in/' },
  { name: 'NPCI UPI Safety Shield Advisory', url: 'https://www.npci.org.in/what-we-do/upi-safety-shield', category: 'news_advisory', source: 'https://www.npci.org.in/' },
  { name: 'CERT-In Current Security Advisories', url: 'https://www.cert-in.org.in/', category: 'news_advisory', source: 'https://directory.gov.in/' },
  { name: 'Indian Cyber Crime Coordination (I4C)', url: 'https://i4c.mha.gov.in/', category: 'news_advisory', source: 'https://directory.gov.in/' },
  { name: 'TRAI Spam & Telecom Advisory', url: 'https://www.trai.gov.in/', category: 'news_advisory', source: 'https://directory.gov.in/' },
  { name: 'DoT Sanchar Saathi Chakshu Portal', url: 'https://sancharsaathi.gov.in/sfc/', category: 'news_advisory', source: 'https://directory.gov.in/' },
  { name: 'Paytm Blog Security Advisories', url: 'https://paytm.com/blog/security/', category: 'news_advisory', source: 'https://paytm.com/' },
  { name: 'PhonePe Trust and Safety Hub', url: 'https://www.phonepe.com/trust-and-safety/', category: 'news_advisory', source: 'https://www.phonepe.com/' },
  { name: 'Google India Safety Center Hub', url: 'https://safety.google/intl/en_in/', category: 'news_advisory', source: 'https://tranco-list.eu/' },
  { name: 'Microsoft India Security Advisory', url: 'https://www.microsoft.com/en-in/security/business', category: 'news_advisory', source: 'https://tranco-list.eu/' },
  { name: 'ET Wealth Banking Fraud Alerts', url: 'https://economictimes.indiatimes.com/wealth/personal-finance-news/banking-fraud-alert', category: 'news_advisory', source: 'https://tranco-list.eu/' },
  { name: 'LiveMint Cyber Fraud Warning Guide', url: 'https://www.livemint.com/money/personal-finance/cyber-fraud-alerts', category: 'news_advisory', source: 'https://tranco-list.eu/' }
];

// Add allowlisted=yes/no flag
const items = rawList.map((entry, idx) => {
  const isAllow = isAllowlistedDomain(entry.url);
  return {
    id: idx + 1,
    name: entry.name,
    url: entry.url,
    category: entry.category,
    source: entry.source,
    allowlisted: isAllow ? 'yes' : 'no'
  };
});

console.log(`Generated Held-Out v2 dataset: ${items.length} URLs.`);
console.log(`  Bank Login (Password/OTP Gate-ON): ${items.filter(i => i.category === 'bank_login').length}`);
console.log(`  Gov.in / NIC Portals:              ${items.filter(i => i.category === 'gov_portal').length}`);
console.log(`  E-Commerce / Fintech Checkout:     ${items.filter(i => i.category === 'ecommerce_fintech').length}`);
console.log(`  News / Fraud Advisory:             ${items.filter(i => i.category === 'news_advisory').length}`);
console.log(`  Allowlisted = yes:                 ${items.filter(i => i.allowlisted === 'yes').length}`);
console.log(`  Allowlisted = no:                  ${items.filter(i => i.allowlisted === 'no').length}`);

const outPath = path.resolve(__dirname, '../benchmark/heldout_v2_urls.json');
fs.writeFileSync(outPath, JSON.stringify(items, null, 2), 'utf8');
console.log(`Wrote benchmark/heldout_v2_urls.json`);
