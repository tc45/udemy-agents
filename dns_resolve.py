import asyncio
import random
import string
import dns.resolver
import dns.asyncresolver
import dns.query
import dns.zone
import dns.reversename
from tabulate import tabulate

COMMON_SUBDOMAINS = [
    "www", "mail", "ftp", "api", "dev", "test", "staging", "admin", "portal", "ns1", "ns2"
]
COMMON_RECORD_TYPES = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME', 'SOA']

results = []

async def check_wildcard(domain):
    print("\n[+] Checking for wildcard DNS...")
    resolver = dns.asyncresolver.Resolver()
    random_host = ''.join(random.choices(string.ascii_lowercase, k=12)) + '.' + domain
    try:
        answers = await resolver.resolve(random_host, 'A')
        ips = [r.to_text() for r in answers]
        print(f"[!] Wildcard detected: {random_host} -> {ips}")
        return ips
    except:
        print("[+] No wildcard detected.")
        return []

async def reverse_lookup(ip_address):
    try:
        rev_name = dns.reversename.from_address(ip_address)
        resolved = dns.resolver.resolve(rev_name, "PTR")
        return resolved[0].to_text().rstrip(".")
    except:
        return None

async def query_record(domain, record_type):
    try:
        answers = await dns.asyncresolver.resolve(domain, record_type)
        ttl = answers.rrset.ttl if answers.rrset else None
        records = []

        for rdata in answers:
            ip = rdata.to_text()
            ptr = None
            if record_type == "A":
                ptr = await reverse_lookup(ip)
            records.append({
                "entry": domain,
                "record_type": record_type,
                "value": ip,
                "ttl": ttl,
                "ptr": ptr
            })

        return records
    except Exception:
        return []

async def enumerate_records(domain):
    print(f"\n[+] Querying DNS records for: {domain}")
    tasks = [query_record(domain, rt) for rt in COMMON_RECORD_TYPES]
    results_nested = await asyncio.gather(*tasks)
    for record_set in results_nested:
        results.extend(record_set)

async def brute_force_subdomains(domain, wildcard_ips):
    print(f"\n[+] Brute-forcing subdomains...")
    resolver = dns.asyncresolver.Resolver()

    async def query(sub):
        fqdn = f"{sub}.{domain}"
        try:
            answers = await resolver.resolve(fqdn, 'A')
            ips = [r.to_text() for r in answers]
            ttl = answers.rrset.ttl
            if set(ips) != set(wildcard_ips):
                for ip in ips:
                    ptr = await reverse_lookup(ip)
                    results.append({
                        "entry": fqdn,
                        "record_type": "A",
                        "value": ip,
                        "ttl": ttl,
                        "ptr": ptr
                    })
        except:
            pass

    tasks = [query(sub) for sub in COMMON_SUBDOMAINS]
    await asyncio.gather(*tasks)

def attempt_axfr(domain):
    print(f"\n[+] Attempting AXFR (Zone Transfer)...")
    try:
        ns_records = dns.resolver.resolve(domain, 'NS')
        for ns in ns_records:
            try:
                ns_ip = dns.resolver.resolve(ns.to_text(), 'A')[0].to_text()
                zone = dns.zone.from_xfr(dns.query.xfr(ns_ip, domain, timeout=5))
                if zone:
                    print(f"[!] Zone Transfer successful on {ns} ({ns_ip})")
                    for name, node in zone.nodes.items():
                        for rdata in node.rdatasets:
                            print(f"{name}.{domain} [{rdata.rdtype}] -> {rdata}")
                    return
            except Exception as e:
                print(f"[X] Failed AXFR from {ns.to_text()} ({ns_ip}): {e}")
    except Exception as e:
        print(f"[X] Error fetching NS records: {e}")

async def main():
    domain = input("Enter domain to enumerate: ").strip()
    wildcard_ips = await check_wildcard(domain)
    await enumerate_records(domain)
    await brute_force_subdomains(domain, wildcard_ips)
    attempt_axfr(domain)

    print("\n\n📋 DNS Enumeration Results:\n")
    table = [
        [r["entry"], r["record_type"], r["value"], r["ttl"], r.get("ptr", "-")]
        for r in results
    ]
    print(tabulate(table, headers=["Entry", "Record Type", "IP/Value", "TTL", "PTR (Reverse)"]))

if __name__ == "__main__":
    asyncio.run(main())
