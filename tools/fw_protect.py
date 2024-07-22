#!/usr/bin/env python

# Copyright 2024 The MITRE Corporation. ALL RIGHTS RESERVED
# Approved for public release. Distribution unlimited 23-02181-25.

"""
Firmware Bundle-and-Protect Tool

"""
import argparse
from pwnlib.util.packing import p16
import json
import os
from Crypto.Cipher import AES
from Crypto.PublicKey import ECC
from Crypto.Signature import eddsa
from Crypto.Hash import HMAC, SHA512
import base64

def protect_firmware(infile: str, outfile: str, version: int, message: str, secret_file: str):
    # Load firmware binary from infile
    with open(infile, mode="rb") as fp:
        firmware = fp.read()

    # Read secrets as a JSON file
    with open(secret_file, mode="r") as fp:
        secrets = json.load(fp)

    # Pack version and size into two little-endian shorts
    metadata = p16(version, endian='little') + \
        p16(len(firmware), endian='little')

    # Combine parts into single firmware blob
    firmware_blob = metadata + firmware + message.encode('ascii') + b"\x00"

    # Sign firmware blob using Ed25519
    ed25519_private_key = base64.b64decode(secrets["ed25519_private_key"])
    ed25519_private_key = ECC.import_key(ed25519_private_key)
    signer = eddsa.new(ed25519_private_key, mode='rfc8032')
    signature = signer.sign(firmware_blob)
    signed_firmware_blob = firmware_blob + signature

    # Generate AES key for CBC mode
    aes_key = base64.b64decode(secrets["aes_key"])

    # Encrypt the signed firmware blob using AES CBC
    aes_iv = os.urandom(16)
    cipher = AES.new(aes_key, AES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(signed_firmware_blob, AES.block_size))

    protected_firmware = aes_iv + ct_bytes
    
    # Write JSON result to outfile
    with open(outfile, mode="wb+") as outfile:
        outfile.write(protected_firmware)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Firmware Protection Tool")
    parser.add_argument(
        "--infile", help="Path to the firmware image to protect.", required=True)
    parser.add_argument(
        "--outfile", help="Filename for the output firmware.", required=True)
    parser.add_argument(
        "--version", help="Version number of this firmware.", required=True, type=int)
    parser.add_argument(
        "--message", help="Release message for this firmware.", required=True)
    parser.add_argument(
        "--secrets", help="Path to the secrets json file.", required=True)
    args = parser.parse_args()

    protect_firmware(infile=args.infile, outfile=args.outfile, version=args.version, message=args.message, secret_file=args.secrets)
