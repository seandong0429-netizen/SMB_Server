import json
import base64
import datetime
import argparse
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization

# --- PRIVATE KEY (KEEP SAFE) ---
PRIVATE_KEY_PEM = b"""-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDJN4F0RuSWjwAk
WMw39k5w+p/QhgNEhtJ7d3U/6oc8M+qY40AgXRAsHHZIM12zA7slgcr2siDjUczi
UnQiNit4SZZY4qu0GFEM7BcdJEAZuHgrNYVQFKt7oSU2mj6DyeG4WTga1oNfrfPW
MBFIkhsLfmn6A6E3iDBx86HLQ5FpIiQ54uDyXkBUOMSQ6pK86cg7hCigLZDNj9UR
o08r949da7mWZ4Io+Cy9J973g0Y+r9TGCzdScBb3yagHPI9FnFjM7R8u6i4ypuni
qgn748Fj8R7dp7MUCOjKw5tHrTpD1ftOv8W3yRCuha+FpfpQjJimDATlQYbfhcpQ
Z6Az5hXBAgMBAAECggEASbQcpYBQO7veo/GowDjmy6hpwKJN8RxnXdVIa+SWq50i
qeTXuOMNyPKV+uVhxXAw7VCpDQr7U/jDEQV9x4hLDPD7csx4c2vSyGZ0IvcDycgR
sFYW4lnn5E2HCYSfMHvSw8lebSo1Ded0YPjTY98sq92eqPcKZwJqKFtC4Ob7jOPP
vW/NuE/NWyZroeMCFQJrt7DGJLvNUWKTgP14IlRwjFtPAuQggUMMO9CcHG7wqW+0
o6w+q+X2jImQYFyigLS6idgrVsdaJTefd4MbC6QIPWU65DfFf+bXtS1hHRkAeEWO
efSdvHHu5oNnyxs/XtzOttE4p+JOAyrj6GtWF7P1zwKBgQDq/KfwEiSU9ULaBcuL
NA0gOXghTvuh6vqcV8mYAzLJRBGFlrQOCwM1LjJ/NUDaqMsfhKZZ8z9f6/DwRaJS
KxKkFE7vHWfupAVln6k13kqN7ZG6JD4Zlez01ryDlL7fihrEmC6xd8VTwe3zZc30
ve2WS1lMRLWIYLPou11jqeJ1GwKBgQDbNcfjZoDrrpp5CRdBa3oFPSB6n74y+WJW
o28+FylGVqben8/pg+q+04PexO4n6AZ7FreOiPil/9/wOry+hWK4Y41yxLE9sK8r
k50Cxjhl10i5PSFBqmImJkbO5l5kWjYqCz63nrYKRFyAo6R8tlbLrBJ5vTUWTxPA
1vgMa/Y6UwKBgQC+70p5vBQzYNHQG3NXCZU8wNWGowm9eBPn40DvnnGurftaw6hL
3NDfbkkjqZ6nzQ027+7HGeo9w5XDdaE+CLed0M6OZiNj+axU9ZVlKtkDV6zYRcib
u4GNM8p7U+p/8lRrt4gBNWOF+gahhfACVCzvuQu2+AFU7dZhXZS1fX1/TwKBgQDP
joOeT/7/qQpAUhg/7CjT7wXitYAcub6f9A2vh7SgEgncPwtYunw5hQKWmnY5ONty
DpdskUqFutnpl2QBLUDFABX9NjnwBGxH4XPIHbFm1EnagwQLLe3S22kuHDgB4tzo
QE95AwCwhfvkHY3wO6HBJUM1G665WdSFQcYJ1OuGWwKBgHVLgeU+YwOUb3IGvWhY
iChmHgTavGOPjnC1LSsc2Skg9yoxInXO15AgTEJILr4NvCINLW48hZyY85evkBux
axUeRIa43LG50Ls7s1eSuAgd+GsRYmt0zSIEFJpILYDci4s8aXX7235hZyUjuZVG
InfjqCidjuLYwSysvdWgg3Wx
-----END PRIVATE KEY-----"""
# -------------------------------

def generate_license(expire_date_str, version="PRO"):
    """
    Generate a signed license file.
    expire_date_str: "YYYY-MM-DD"
    """
    # 1. Prepare Data
    data = {
        "ExpiryDate": expire_date_str,
        "Version": version,
        "GeneratedAt": datetime.datetime.now().isoformat()
    }
    json_data = json.dumps(data).encode('utf-8')

    # 2. Sign Data
    private_key = serialization.load_pem_private_key(
        PRIVATE_KEY_PEM,
        password=None
    )
    
    signature = private_key.sign(
        json_data,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

    # 3. Pack License (Base64 Data + Base64 Signature)
    # Format: Base64(Data) . Base64(Signature)
    b64_data = base64.b64encode(json_data).decode('utf-8')
    b64_sig = base64.b64encode(signature).decode('utf-8')
    license_content = f"{b64_data}.{b64_sig}"

    # 4. Save
    with open("license.lic", "w") as f:
        f.write(license_content)
    
    print(f"✅ Success! Generated license.lic valid until {expire_date_str}")
    print(f"Content Preview: {license_content[:50]}...")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="SMB Server License Generator")
    parser.add_argument("date", help="Expiration Date (YYYY-MM-DD)")
    args = parser.parse_args()
    
    try:
        # Validate date format
        datetime.datetime.strptime(args.date, "%Y-%m-%d")
        generate_license(args.date)
    except ValueError:
        print("❌ Error: Date must be in YYYY-MM-DD format.")
