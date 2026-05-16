import urllib.request
import re

url = "https://packetstormsecurity.com/search/?q=WordPress"
headers = {"User-Agent": "Mozilla/5.0"}
req = urllib.request.Request(url, headers=headers)
with urllib.request.urlopen(req) as resp:
    print(f"Status Code: {resp.getcode()}")
    html = resp.read().decode('utf-8', errors='ignore')
    print(html[:5000])
