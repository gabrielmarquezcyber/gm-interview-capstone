"""
CVE Prioritization Engine

Pulls NVD, EPSS, and CISA KEV data into a unified scoring model so a
Vulnerability Management or Detection Engineering team can decide what
to patch or monitor first. In a real environment this would be joined
with an asset inventory to surface "Top CVEs on critical systems".
"""

import io
import os
import time
import random
import requests
import pandas as pd
import matplotlib.pyplot as plt
from datetime import datetime, timedelta
from pathlib import Path

try:
    from dotenv import load_dotenv
    load_dotenv()
except Exception:
    # dotenv is optional; if not installed, environment variables
    # can still be provided via the shell/OS.
    pass

# =========================================================
# CONFIGURATION
# =========================================================
LOOKBACK_DAYS = 30          # how many days of NVD CVEs to fetch
PAGE_SIZE = 2000            # NVD max results per page
RATE_DELAY = 12             # seconds between paged calls if no API key
NVD_API_KEY = os.getenv("NVD_API_KEY", "").strip()  # loaded from .env

# Resolve repo root relative to this file:
#   .../elastic-siem-detection-vuln-prioritization/artifacts/scripts/cve_prioritizer.py
# parents[0] = scripts/, parents[1] = artifacts/, parents[2] = repo root
REPO_ROOT = Path(__file__).resolve().parents[2]

# Output directory (repo-relative, consistent with the README)
OUT_DIR = REPO_ROOT / "artifacts" / "figures"
OUT_DIR.mkdir(parents=True, exist_ok=True)
OUT_CSV = OUT_DIR / "priority.csv"
OUT_PNG = OUT_DIR / "priority_chart.png"

# Debug: print whether API key loaded
if NVD_API_KEY:
    print(f"[INFO] NVD API key loaded: {NVD_API_KEY[:8]}...")
else:
    print("[WARN] No NVD API key found - will use rate-limited requests")

# =========================================================
# HELPER FUNCTION: robust JSON GET with retries
# =========================================================
def safe_get_json(
    url,
    *,
    params=None,
    headers=None,
    timeout=120,
    max_retries=6,
    min_sleep=5,
    max_sleep=20,
):
    """
    Robust GET→JSON with retries, jitter, and helpful logs.

    Returns:
        (ok, json_dict_or_none, last_status_code, last_text_snippet)
    """
    last_status = None
    last_text_snippet = None
    for attempt in range(1, max_retries + 1):
        try:
            r = requests.get(url, params=params, headers=headers, timeout=timeout)
            last_status = r.status_code
            last_text_snippet = (r.text[:200] if r.text else "")
            if r.status_code == 200:
                try:
                    return True, r.json(), r.status_code, last_text_snippet
                except ValueError:
                    # JSON parse error, fall through to retry logic below
                    pass

            # Retry on typical transient status codes
            if r.status_code in (429, 403, 502, 503, 504):
                sleep_s = random.randint(min_sleep, max_sleep)
                print(
                    f"[NVD] HTTP {r.status_code} "
                    f"(attempt {attempt}/{max_retries}) - retrying in {sleep_s}s"
                )
                time.sleep(sleep_s)
                continue

            # Non-retriable status; break out
            break

        except requests.RequestException as e:
            sleep_s = random.randint(min_sleep, max_sleep)
            print(
                f"[NVD] Request exception {e} "
                f"(attempt {attempt}/{max_retries}) - retrying in {sleep_s}s"
            )
            time.sleep(sleep_s)

    return False, None, last_status, last_text_snippet


# =========================================================
# 1) EPSS (Exploit Prediction Scoring System)
# =========================================================
print("[+] Downloading EPSS feed...")
epss_url = "https://epss.cyentia.com/epss_scores-current.csv.gz"
epss_gz = requests.get(epss_url, timeout=60).content
epss = pd.read_csv(io.BytesIO(epss_gz), compression="gzip", skiprows=1)
epss.columns = epss.columns.str.lower()
epss = epss.rename(columns={"cve": "CVE", "epss": "EPSS"})
epss["EPSS"] = pd.to_numeric(epss["EPSS"], errors="coerce").fillna(0.0)
print(f"    EPSS entries loaded: {len(epss)}")

# =========================================================
# 2) CISA KEV (Known Exploited Vulnerabilities)
# =========================================================
print("[+] Downloading CISA KEV feed...")
kev_url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
kev = requests.get(kev_url, timeout=120).json()
kev_set = {
    item.get("cveID")
    for item in kev.get("vulnerabilities", [])
    if item.get("cveID")
}
print(f"    KEV entries loaded: {len(kev_set)}")

# =========================================================
# 3) NVD CVE DATA (30-day window, paginated)
# =========================================================
print(f"[+] Downloading NVD CVEs (last {LOOKBACK_DAYS} days)...")
nvd_base = "https://services.nvd.nist.gov/rest/json/cves/2.0"
end_date = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.000")
start_date = (datetime.utcnow() - timedelta(days=LOOKBACK_DAYS)).strftime(
    "%Y-%m-%dT%H:%M:%S.000"
)
headers = {
    "User-Agent": "gabrielmarquezcyber-cve-prioritizer/1.0",
    "apiKey": NVD_API_KEY,
} if NVD_API_KEY else {
    "User-Agent": "gabrielmarquezcyber-cve-prioritizer/1.0",
}

rows = []
total_results = None
start_index = 0

while True:
    params = {
        "lastModStartDate": start_date,
        "lastModEndDate": end_date,
        "resultsPerPage": PAGE_SIZE,
        "startIndex": start_index,
    }
    ok, data, status, snippet = safe_get_json(
        nvd_base, params=params, headers=headers, timeout=120
    )

    if not ok or not isinstance(data, dict):
        print(f"[NVD] Failed to fetch JSON. status={status}, snippet={repr(snippet)}")
        break

    vulns = data.get("vulnerabilities", [])
    for v in vulns:
        cve = v.get("cve", {})
        cve_id = cve.get("id")
        metrics = cve.get("metrics", {})
        cvss = None

        if "cvssMetricV31" in metrics and metrics["cvssMetricV31"]:
            cvss = metrics["cvssMetricV31"][0]["cvssData"]["baseScore"]
        elif "cvssMetricV30" in metrics and metrics["cvssMetricV30"]:
            cvss = metrics["cvssMetricV30"][0]["cvssData"]["baseScore"]

        rows.append(
            {
                "CVE": cve_id,
                "CVSS": float(cvss) if cvss is not None else 0.0,
            }
        )

    if total_results is None:
        total_results = data.get("totalResults", len(vulns))

    if len(vulns) < PAGE_SIZE or (start_index + PAGE_SIZE) >= total_results:
        break

    # NVD API recommends spacing requests, especially without an API key
    if not NVD_API_KEY:
        print(f"[NVD] Sleeping {RATE_DELAY}s to respect rate limits...")
        time.sleep(RATE_DELAY)

    start_index += PAGE_SIZE

nvd_df = pd.DataFrame(rows)
if nvd_df.empty:
    print("[NVD] No rows returned - using a minimal fallback row to keep the workflow usable.")
    nvd_df = pd.DataFrame([{"CVE": "CVE-0000-0000", "CVSS": 0.0}])
print(f"    NVD entries processed: {len(nvd_df)}")

# =========================================================
# 4) COMBINE AND SCORE
# =========================================================
print("[+] Combining datasets and scoring priorities...")
df = nvd_df.merge(epss[["CVE", "EPSS"]], on="CVE", how="left").fillna({"EPSS": 0.0})
df["KEV"] = df["CVE"].isin(kev_set).astype(int)

# Weighted priority model: KEV and EPSS carry more weight than raw CVSS
df["Priority"] = (df["KEV"] * 40) + (df["EPSS"] * 50) + (df["CVSS"] * 10)
df = df.sort_values("Priority", ascending=False)
print(f"    Combined rows: {len(df)}")

# =========================================================
# 5) OUTPUTS
# =========================================================
print("[+] Saving outputs...")
df.to_csv(OUT_CSV, index=False)

# Create a better chart: Top 5 KEV vs Top 10 Non-KEV
kev_top = df[df["KEV"] == 1].head(5)
non_kev_top = df[df["KEV"] == 0].head(10)
chart_data = pd.concat([kev_top, non_kev_top])

# Sort ascending so highest priority is at top with longest bars
chart_data_sorted = chart_data.sort_values("Priority", ascending=True)

fig, ax = plt.subplots(figsize=(12, 8))
colors = [
    "#d62728" if row["KEV"] == 1 else "#1f77b4"
    for _, row in chart_data_sorted.iterrows()
]
bars = ax.barh(chart_data_sorted["CVE"], chart_data_sorted["Priority"], color=colors)
ax.set_xlabel("Priority Score", fontsize=12)
ax.set_title(
    f"CVE Priority: Top KEV vs Non-KEV - Last {LOOKBACK_DAYS}d",
    fontsize=14,
)

# Add value labels on bars
for i, (idx, row) in enumerate(chart_data_sorted.iterrows()):
    priority = row["Priority"]
    ax.text(priority + 2, i, f"{priority:.1f}", va="center", fontsize=9)

# Add legend
from matplotlib.patches import Patch

legend_elements = [
    Patch(facecolor="#d62728", label="KEV Listed"),
    Patch(facecolor="#1f77b4", label="Not KEV Listed"),
]
ax.legend(handles=legend_elements, loc="lower right")

plt.tight_layout()
plt.savefig(OUT_PNG, dpi=140)
plt.close()

print(f"✅ Saved: {OUT_CSV}")
print(f"✅ Saved: {OUT_PNG}")

# Print summary stats
print("\n" + "=" * 60)
print("SUMMARY STATISTICS")
print("=" * 60)
print(f"Total CVEs analyzed: {len(df)}")
print(f"KEV-listed CVEs: {df['KEV'].sum()}")
print(f"Average Priority Score: {df['Priority'].mean():.2f}")
print(f"High CVSS (>=9.0): {(df['CVSS'] >= 9.0).sum()}")
print(f"High EPSS (>=0.5): {(df['EPSS'] >= 0.5).sum()}")
print("\nTop 5 Overall:")
print(df.head(5)[["CVE", "Priority", "KEV", "EPSS", "CVSS"]].to_string(index=False))
print("=" * 60)
print("[+] Done.")
