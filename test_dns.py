
import dns.resolver

domain = "google.com"
print(f"Testing {domain}")

try:
    print("--- MX ---")
    answers = dns.resolver.resolve(domain, 'MX')
    for rdata in answers:
        print(f"Dir: {dir(rdata)}")
        if hasattr(rdata, 'target'):
            print(f"Target: {rdata.target}")
        if hasattr(rdata, 'exchange'):
            print(f"Exchange: {rdata.exchange}")
except Exception as e:
    print(f"MX Error: {e}")

try:
    print("--- NS ---")
    answers = dns.resolver.resolve(domain, 'NS')
    for rdata in answers:
        if hasattr(rdata, 'target'):
            print(f"Target: {rdata.target}")
except Exception as e:
    print(f"NS Error: {e}")
