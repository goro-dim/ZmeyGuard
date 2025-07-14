TARGET_KEYWORDS = ["examplebank", "example-bank", "exmpl"] #  List of keywords that may appear in phishing domains
TLD_FILTER = ".com" # Only focus on domains within this TLD
OUTPUT_FILE = "tainted_domains_log.csv" # Where all results (new + old) are stored
NEW_ALERTS_FILE = "new_suspicious_domains.csv" # Where new/first-seen suspicious domains are stored
MAX_RETRIES = 3 # Retry strategy when querying crt.sh
RETRY_DELAY = 5 #  seconds between retries
