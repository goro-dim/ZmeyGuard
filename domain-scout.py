import requests
import pandas as pd
import re
import time
from datetime import datetime, timezone

# ✨ CONFIG
TARGET_KEYWORDS = ["dsk", "dskbank", "dsck", "dsk-bg", "bankdsk"]
TLD_FILTER = ".bg"
OUTPUT_FILE = "tainted_domains_log.csv"
NEW_ALERTS_FILE = "new_suspicious_domains.csv"
MAX_RETRIES = 3
RETRY_DELAY = 5  # seconds

def fetch_crtsh_data(keyword):
    print(f"[~] Fetching domains for keyword: {keyword}")
    url = f"https://crt.sh/?q={keyword}.bg&output=json"
    for attempt in range(1, MAX_RETRIES + 1):
        try:
            response = requests.get(url, timeout=15)
            response.raise_for_status()
            return response.json()
        except Exception as e:
            print(f"[!] Attempt {attempt} failed: {e}")
            time.sleep(RETRY_DELAY * attempt)
    return []

def normalize_domain(domain):
    domain = domain.lower().strip()
    if domain.startswith("www."):
        domain = domain[4:]
    return domain

def filter_domains(data, keyword):
    seen = set()
    filtered = []
    for entry in data:
        name_value = entry.get("name_value", "")
        domains = name_value.split("\n")
        for domain in domains:
            domain = normalize_domain(domain)
            if domain in seen:
                continue
            seen.add(domain)
            if TLD_FILTER in domain and keyword in domain:
                filtered.append({
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "domain": domain,
                    "source": "crt.sh",
                    "matched_keyword": keyword
                })
    return filtered

def save_results(results):
    if not results:
        print("[✓] No suspicious domains found.")
        return

    df_new = pd.DataFrame(results)

    try:
        df_existing = pd.read_csv(OUTPUT_FILE)
        df_combined = pd.concat([df_existing, df_new]).drop_duplicates("domain")
        new_entries = df_combined[~df_combined["domain"].isin(df_existing["domain"])]
    except FileNotFoundError:
        df_combined = df_new
        new_entries = df_new

    df_combined.to_csv(OUTPUT_FILE, index=False)

    if not new_entries.empty:
        new_entries.to_csv(NEW_ALERTS_FILE, index=False)
        print(f"[!] {len(new_entries)} NEW suspicious domains logged!")
    else:
        print("[✓] No new suspicious domains detected.")

    print(f"[✓] Logged all results to {OUTPUT_FILE}")

def main():
    print("🧙‍♂️ Initiating Spell: Watcher of the Tainted Domains")
    all_results = []

    for keyword in TARGET_KEYWORDS:
        data = fetch_crtsh_data(keyword)
        results = filter_domains(data, keyword)
        all_results.extend(results)

    # Deduplicate before saving
    seen_domains = set()
    deduped_results = []
    for entry in all_results:
        if entry["domain"] not in seen_domains:
            seen_domains.add(entry["domain"])
            deduped_results.append(entry)

    save_results(deduped_results)

if __name__ == "__main__":
    main()
