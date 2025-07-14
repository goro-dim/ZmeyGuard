# running this will transform the domains from new_suspicious_domains.csv to ips
import csv
import socket

def resolve_domain_to_ip(domain):
    try:
        return socket.gethostbyname(domain)
    except:
        return None

def extract_ips_from_csv(csv_path):
    domains = set()
    ips = set()

    with open(csv_path, "r") as f:
        reader = csv.DictReader(f)
        for row in reader:
            domain = row["domain"]
            if domain:
                domain = domain.strip().lower()
                ip = resolve_domain_to_ip(domain)
                if ip:
                    ips.add(ip)

    return list(ips)

if __name__ == "__main__":
    ips = extract_ips_from_csv("new_suspicious_domains.csv")
    for ip in ips:
        print(ip)
