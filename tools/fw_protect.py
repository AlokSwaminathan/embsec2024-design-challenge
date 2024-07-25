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
import pathlib
from Crypto.Cipher import AES
from Crypto.PublicKey import ECC
from Crypto.Signature import eddsa
from Crypto.Util.Padding import pad
import base64

REPO_ROOT = pathlib.Path(__file__).parent.parent.absolute()

def protect_firmware(infile: str, outfile: str, version: int, message: str, secret_file: str,debug: bool):
    # Load firmware binary from infile
    with open(infile, mode = "rb") as fp:
        firmware = fp.read()

    # Read secrets as a JSON file
    with open(secret_file, mode = "r") as fp:
        secrets = json.load(fp)

    # Pack version and size into two little-endian shorts
    metadata = p16(version, endian = 'little') + \
        p16(len(firmware), endian = 'little')
        
    if debug:
      print(f"Version: {version}\nFirmware Size: {len(firmware)}")

    # Combine parts into single firmware blob
    firmware_blob = metadata + firmware + message.encode('ascii') + b"\x00"
    if debug:
      firmware_hex_string = ' '.join([f'{byte:02x}' for byte in firmware_blob])
      firmware_hex_string = firmware_hex_string[:300] + "..."
      print(f"Firmware Blob: {firmware_hex_string}")

    # Sign firmware blob using Ed25519
    ed25519_private_key = base64.b64decode(secrets["ed25519_private_key"])
    ed25519_private_key = ECC.import_key(ed25519_private_key, curve_name='ed25519')
    signer = eddsa.new(ed25519_private_key, mode = 'rfc8032')
    signature = signer.sign(firmware_blob)
    if debug:
      signature_hex_string = ' '.join([f'{byte:02x}' for byte in signature])
      print(f"Signature: {signature_hex_string}")
    signed_firmware_blob = firmware_blob + signature
    if debug:
      with open("signed_firmware_blob.hex", mode = "wb+") as signed_firmware:
        signed_firmware.write(signed_firmware_blob)
    print("Ed25519 signature generated.")

    # Generate AES key for CBC mode
    aes_key = base64.b64decode(secrets["aes_key"])

    # Encrypt the signed firmware blob using AES CBC
    aes_iv = os.urandom(16)
    cipher = AES.new(aes_key, AES.MODE_CBC, iv=aes_iv)
    ct_bytes = cipher.encrypt(pad(signed_firmware_blob, AES.block_size))

    protected_firmware = aes_iv + ct_bytes
    if debug:
      protected_hex_string = ' '.join([f'{byte:02x}' for byte in protected_firmware])
      print(f"AES IV: {protected_hex_string[:48]}")
      print(f"Encrypted Data: {protected_hex_string[48:300]}...");
    
    print("AES encryption successful.")
    
    # Write JSON result to outfile
    with open(outfile, mode = "wb+") as protected_binary:
        protected_binary.write(protected_firmware)


def parse_args(secrets="secret_build_output.json"):
    parser = argparse.ArgumentParser(description = "Firmware Protection Tool")
    parser.add_argument(
        "--infile", help = "Path to the firmware image to protect.", required = True)
    parser.add_argument(
        "--outfile", help = "Filename for the output firmware.", required = True)
    parser.add_argument(
        "--version", help = "Version number of this firmware.", required = True, type = int)
    parser.add_argument(
        "--message", help = "Release message for this firmware.", required = True, type = str)
    parser.add_argument(
        "--secrets", help = "Path to the secrets json file.", default = REPO_ROOT/"secret_build_outputs.json")
    parser.add_argument(
        "--debug", help = "Enable debugging messages.", action = "store_true"
    )
    args = parser.parse_args()
    if args.version < 0 or args.version > 65535:
        parser.error("Version number must be between 0 and 65535.")
    if len(args.message) > 1020:
        parser.error("Release message must be less than 1020 characters.")
    return args

# parameters for compiling function in terminal
if __name__ == "__main__": 
    args = parse_args()
    protect_firmware(infile = args.infile, 
                     outfile = args.outfile, 
                     version = args.version, 
                     message = args.message, 
                     secret_file = args.secrets,
                     debug = args.debug)