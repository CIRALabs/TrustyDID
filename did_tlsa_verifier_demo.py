from typing import Any
from hashlib import sha256
import json
import sys
import requests
import multibase
import base58
import dns.resolver
from dns.resolver import Answer
from dns.rdtypes.ANY.TLSA import TLSA
from jwcrypto import jwk
from cryptography.hazmat.primitives import serialization, asymmetric


# TLSA URIs have the general form: someid._sometype.someorigin
TLSA_URI_REGEX = r".*\.\_.*\..*"

RESOLVER_URL = 'https://uniresolver.io/1.0/identifiers/'
URI = 'URI'
TLSA = 'TLSA'
# Hardcoding the origin as we do not have a way to extract it from the DID...yet
ORIGIN = 'tr-demo.ciralabs.ca'
HEADER = '\033[92m'
ENDC = '\033[0m'


class InvalidKeyFormat(Exception):
    pass


class DIDResolutionFailure(Exception):
    pass


def resolve_did(did: str) -> dict:
    """
    Resolves a DID to a DID Document.

    Args:
        did (str): The DID to be resolved. Ex: did:sov:1234abc

    Raises:
        DIDResolutionFailure: The universal resolver was unable to resolve the DID to a DID Document.

    Returns:
        dict: The DID Document.
    """
    response = requests.get(f'{RESOLVER_URL}{did}', timeout=10)
    did_document = response.json()['didDocument']
    if did_document is None:
        raise DIDResolutionFailure
    return did_document


def resolve_dns_records(record_type: str, record_name: str) -> (Any | Answer):
    """
    Resolves a DNS record/s.

    Args:
        record_type (str): The RRType of the record to be resolved.
        record_name (str): The name of the record to be resolved.

    Returns:
        Answer: The answer to the DNS query.
    """
    try:
        print(
            f'{HEADER}Attempting to resolve {record_type} records for:{ENDC} {record_name}{HEADER}...{ENDC}')
        dns_answers = dns.resolver.resolve(record_name, record_type)
    except Exception as exc:
        print(exc)
        print(
            f'{HEADER}DNS resolution for{ENDC} {record_name} {HEADER}{record_type} records failed.{ENDC}')
        sys.exit()
    print(f'{HEADER}DNS resolution successful.{ENDC}')
    print(
        f'{HEADER}{record_type} records:{ENDC} {[rdata.to_text() for rdata in dns_answers]}\n')
    return dns_answers


def convert_verification_method_key_to_hex(verification_method: dict) -> str:
    """
    Converts the public key represented by a verification method into a hex encoded DER format.

    Args:
        verification_method (dict): A Verification Method object as defined in did-core.

    Raises:
        InvalidKeyFormat: Key is encoded or represented in an unsupported format.

    Returns:
        str: The hex encoded DER format of the key.
    """
    if verification_method.get('publicKeyJwk'):
        key = jwk.JWK(**verification_method['publicKeyJwk'])
        key_der = serialization.load_pem_public_key(key.export_to_pem())
        return key_der.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.SubjectPublicKeyInfo).hex()
    if verification_method.get('publicKeyMultibase'):
        key = serialization.load_der_public_key(
            multibase.decode(verification_method['publicKeyMultibase']))
        return key.public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.SubjectPublicKeyInfo).hex()
    if verification_method.get('publicKeyBase58'):
        if verification_method['type'] == 'Ed25519VerificationKey2018':
            key = asymmetric.ed25519.Ed25519PublicKey.from_public_bytes(
                base58.b58decode(verification_method['publicKeyBase58']))
        elif verification_method['type'] == 'X25519KeyAgreementKey2019':
            key = asymmetric.x25519.X25519PublicKey.from_public_bytes(
                base58.b58decode(verification_method['publicKeyBase58']))
        else:
            key = serialization.load_der_public_key(
                base58.b58decode(verification_method['publicKeyBase58']))
        return key.public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()
    raise InvalidKeyFormat('Unrecognized Verification Key format.')


def tlsa_verify_public_key(tlsa_record: TLSA, public_key: str) -> bool:
    """
    Attempts to match a public key to the content of a TLSA record

    Args:
        tlsa_record (TLSA): A TLSA resource record.
        public_key (str): A hex encoded DER format public key.

    Returns:
        bool: True if the key matches the record content, false otherwise.
    """
    print(f'{HEADER}Attempting to match TLSA record:{ENDC} {rdata.to_text()}...')
    if tlsa_record.mtype == 0:
        print(f'{HEADER}Matching type:{ENDC} {tlsa_record.mtype}{HEADER}, matching unhashed public key...{ENDC}')
        if tlsa_record.cert.hex() == public_key:
            print(
                f'{HEADER}Successfull key match. TLSA verification successful.{ENDC}\n')
            return True
    if tlsa_record.mtype == 1:
        print(f'{HEADER}Matching type:{ENDC} {tlsa_record.mtype}{HEADER}, matching SHA-256 hash of public key...{ENDC}')
        key_sha256_hash = sha256(public_key.encode()).hexdigest()
        print(f'{HEADER}Key SHA256 hash:{ENDC} {key_sha256_hash}')
        if tlsa_record.cert.hex() == key_sha256_hash:
            print(
                f'{HEADER}Successfull key match. TLSA verification successful.{ENDC}\n')
            return True
    print(
        f'{HEADER}Unsuccessful key match using TLSA record:{ENDC} {rdata.to_text()}\n')
    return False


if __name__ == '__main__':
    # Prompt user to enter a DID to verify via DNS/TLSA
    while True:
        did = input(
            f'{HEADER}Please enter a DID you wish to verify via DNS/TLSA:{ENDC}\n')
        # Attempt to resolve DID document
        try:
            did_document = resolve_did(did)
            print(
                f'{HEADER}Resolved DID document:{ENDC}{json.dumps(did_document, indent=2)}\n')
            break
        # If DID resolution fails, print error message and continue prompting
        except DIDResolutionFailure:
            print(f'{HEADER}Unable to resolve{ENDC} {did}')
            continue

    # Set the DID URI record and TLSA record IDs
    did_uri_record_id = f'_did.{ORIGIN}'
    did_tlsa_record_id = f'_did.{ORIGIN}'

    # Attempt to resolve URI records for the DID
    dns_answers = resolve_dns_records(URI, did_uri_record_id)

    # Verify that the DID matches the target value of URI record
    print(f'{HEADER}Verifying DID matches target value of URI record...{ENDC}')
    if did not in [rdata.target.decode('utf-8') for rdata in dns_answers]:
        # If DID doesn't match URI record, print error message and exit
        print(
            f'{HEADER}No URI records found matching{ENDC} {did}, {HEADER}DNS verification failed.{ENDC}')
        sys.exit()
    # Print success message if DID matches URI record
    print(f'{HEADER}Match found.{ENDC}\n')

    # Attempt to resolve TLSA records corresponding to the related domain for the DID
    # Please note that this would be extracted from the DID Document under normal circumstances,
    # but under the contraints of this demo it has been hardcoded.
    dns_answers = resolve_dns_records(TLSA, did_tlsa_record_id)

    did_key_ids = [verification_method["id"]
                   for verification_method in did_document["verificationMethod"]]
    # Prompt user to select which key/verificationMethod they would like to match against the TLSA records
    while True:
        key_choice = input(
            f'{HEADER}Please select which key you would like to match against the TLSA records:{ENDC} {did_key_ids}\n')
        if key_choice in set(did_key_ids):
            break
        print(f'{HEADER}Please enter a valid key id:{ENDC} {did_key_ids}')
        continue
    # Extract the selected verificationMethod from the DID document
    verification_method = next(
        (verification_method for verification_method in did_document["verificationMethod"] if verification_method['id'] == key_choice))
    # Print the selected verificationMethod
    print(
        f'\n{HEADER}verificationMethod selected:{ENDC} {json.dumps(verification_method, indent=2)}')

    # Convert the public key to hex
    key_hex_format = convert_verification_method_key_to_hex(
        verification_method)
    # Print the hex encoded key
    print(f'{HEADER}verificationMethod public key as hex:{ENDC} {key_hex_format}\n')

    # Match the selected public key against the content of the resolved TLSA records
    match = False
    for rdata in dns_answers:
        if tlsa_verify_public_key(rdata, key_hex_format):
            match = True
    if not match:
        # If the key doesn't match the record content, print an error message and exit
        print(
            f'{HEADER}TLSA verification of{ENDC} {did} {HEADER}unsuccessful. The key was not matched against any of the resolved TLSA records.{ENDC}')
        sys.exit()

    # Attempt to resolve URI records to determine the domain's trust registry membership claim
    print(f'{HEADER}Determining Trust Registry membership of origin:{ENDC} {ORIGIN}')
    dns_answers = resolve_dns_records(URI, f'_tr.{ORIGIN}')

    # Prompt user to select which trust registry they would like to confirm the domain's membership in
    tr_choices = [rdata.target.decode('utf-8') for rdata in dns_answers]
    while True:
        tr_choice = input(
            f'{HEADER}Please select which Trust Registry you would like to verify{ENDC} {ORIGIN}\'{HEADER}s membership in:{ENDC} {tr_choices}\n')
        if tr_choice in set(tr_choices):
            break
        print(f'{HEADER}Please enter a Trust Registry:{ENDC} {tr_choices}')
        continue

    # Construct the tr membership TLSA record name from the user's choice
    tr_membership_record = f'{ORIGIN}._tr.{tr_choice}'
    # Attempt to resolve TLSA records to verify the domain's trust registry membership claim
    dns_answers = resolve_dns_records(TLSA, tr_membership_record)

    # Match the selected public key against the content of the resolved TLSA records
    match = False
    for rdata in dns_answers:
        if tlsa_verify_public_key(rdata, key_hex_format):
            match = True
    if not match:
        # If the key doesn't match the record content, print an error message and exit
        print(
            f'{HEADER}Trust Registry verification unsuccessful. The key was not matched against any of the resolved TLSA records.{ENDC}')
        sys.exit()
    # The public key matches the record hosted by the trust registry!
    print(
        f'{HEADER}Trust Registry verification successful.{ENDC} {ORIGIN} {HEADER}is a member of{ENDC} {tr_choice}.')
