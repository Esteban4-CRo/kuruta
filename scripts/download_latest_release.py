"""Download the latest release assets from GitHub into latest_release folder."""

import json
import urllib.request
from pathlib import Path

API_URL = "https://api.github.com/repos/Esteban4-CRo/kuruta/releases/latest"
req = urllib.request.Request(API_URL, headers={"User-Agent": "Kuruta-Downloader"})

with urllib.request.urlopen(req) as resp:
    data = json.loads(resp.read().decode())

tag_name = data.get("tag_name", "latest")
DEST_DIR = Path(__file__).resolve().parents[1] / f"latest_release_{tag_name}"
DEST_DIR.mkdir(parents=True, exist_ok=True)

assets = data.get("assets", [])
print(f"Release: {tag_name} - Downloading {len(assets)} assets to {DEST_DIR}...")

for a in assets:
    name = a["name"]
    url = a["browser_download_url"]
    size = a["size"]
    target = DEST_DIR / name
    if target.exists() and target.stat().st_size == size:
        print(f"Already downloaded: {name} ({size} bytes)")
        continue
    print(f"Downloading {name} ({size} bytes)...")
    urllib.request.urlretrieve(url, target)
    print(f"Successfully downloaded: {name}")

print("All v0.3.5 assets downloaded successfully.")
