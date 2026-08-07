import json

# Generate a mock list of 1000 domains
domains = [
    "google.com",
    "youtube.com",
    "facebook.com",
    "baidu.com",
    "wikipedia.org",
    "yahoo.com",
    "reddit.com",
    "amazon.com",
    "twitter.com",
    "instagram.com",
    "linkedin.com",
    "netflix.com",
    "live.com",
    "bing.com",
    "office.com",
    "apple.com",
    "microsoft.com",
    "github.com",
    "paypal.com",
    "chase.com"
]

# pad to 1000 with fake domains
for i in range(21, 1001):
    domains.append(f"popular-domain-{i}.com")

with open('tranco_1000.json', 'w') as f:
    json.dump(domains, f, indent=2)

print("Generated tranco_1000.json")
