"""
Standalone keep-alive ping for Render free tier.
Run this as a free cron-job.org / UptimeRobot target,
or as a separate always-on process.

Usage:
  python keepalive.py https://interstellar-modz-server.onrender.com
"""
import sys
import time
import urllib.request

URL = sys.argv[1].rstrip("/") + "/health" if len(sys.argv) > 1 else "http://127.0.0.1:8000/health"
INTERVAL = 600  # 10 minutes

print(f"[keepalive] pinging {URL} every {interval}s")
while True:
    try:
        with urllib.request.urlopen(URL, timeout=15) as r:
            print(f"[ok] {r.status} {r.read()[:80]}")
    except Exception as e:
        print(f"[fail] {e}")
    time.sleep(interval)
