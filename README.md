## DNS based Trust Registry

This repository contains some sample code and documents exploring a Trust Registry implementation rooted in the DNS. It uses a live DID (see `did.txt`) and 2 DNS zones, `tr-demo.ciralabs.ca` and `trustregistry.ca`, as the basis for what such an implementation may look and function like.

Please checkout the .ppt for a more detailed walkthrough of the DNS based Trust Registry implementation. It was originally presented by Jacques Latour at ICANN76.

The sample code can be found in `did_tlsa_verifier_demo.py`.

To execute the demo script please run `python3 did_tlsa_verifier_demo.py` and paste the DID `did:sov:danube:XWfvq6uyAjBUbg4hBBP3vM` at the first prompt.

You may need to install some less common python packages to run the demo:
`pip3 install cryptography py-multibase base58 jwcrypto dnspython`

DIG commands for the DNS records:
To query the **DID URI** record from the command line: 
`dig _did.tr-demo.ciralabs.ca URI +dnssec +multi`

To query the **DID TLSA** records from the command line:
`dig _did.tr-demo.ciralabs.ca TLSA +dnssec +multi`

To query the **Trust Registry URI** record from the command line: 
`dig _tr.tr-demo.ciralabs.ca URI +dnssec +multi`

To query the **Trust Regsitry TLSA** record from the command line: 
`dig tr-demo.ciralabs.ca._tr.trustregistry.ca TLSA +dnssec +multi`