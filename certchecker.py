import ssl
import socket
from datetime import datetime

# Get SSL/TLS certificate expiration date
def get_certificate_expiry(domain):
    context = ssl.create_default_context()
    with socket.create_connection((domain, 443)) as sock:
        with context.wrap_socket(sock, server_hostname=domain) as ssock:
            cert = ssock.getpeercert()
            # Extract the expiration date
            expiry_date = datetime.strptime(cert['notAfter'], "%b %d %H:%M:%S %Y GMT")
            return expiry_date

# Read domains from a file and get expiry dates
def check_certificates(filename):
    with open(filename, "r") as f:
        domains = f.readlines()

    domains = [domain.strip() for domain in domains]

    # Iterate over the list of domains and check certificate expiration
    for domain in domains:
        if domain:  # Ensure the domain is not empty
            try:
                expiry_date = get_certificate_expiry(domain)
                now = datetime.utcnow()

                # Format expiry date as DD.MM/YYYY
                formatted_expiry_date = expiry_date.strftime("%d.%m/%Y")

                # Calculate days left until expiration
                days_left = (expiry_date - now).days

                # Output to terminal
                print(f"Domain: {domain}")
                print(f"  Expires: {formatted_expiry_date}")
                print(f"  Days left before expiration: {days_left}")
                print("")  # For better separation between domains
            except ssl.SSLCertVerificationError:
                print(f"Domain: {domain}")
                print(f"  SSL certificate verification failed")
                print("")  # For separation
            except Exception as e:
                print(f"Domain: {domain}")
                print(f"  Error occurred: {e}")
                print("")  # For separation

# Check certificates from the file.
check_certificates("domains.txt")
