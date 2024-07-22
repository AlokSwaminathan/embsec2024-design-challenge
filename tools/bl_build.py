#!/usr/bin/env python

# Copyright 2024 The MITRE Corporation. ALL RIGHTS RESERVED
# Approved for public release. Distribution unlimited 23-02181-25.

"""
Bootloader Build Tool

This tool is responsible for building the bootloader from source and copying
the build outputs into the host tools directory for programming.
"""
import os
import pathlib
import subprocess
import json
from Crypto.PublicKey import ECC
import base64

# Define root directory and bootloader directory 
REPO_ROOT = pathlib.Path(__file__).parent.parent.absolute()
BOOTLOADER_DIR = os.path.join(REPO_ROOT, "bootloader")

def padded_char_array(str):
    char_array = "{" + ", ".join([f"'{c}'" for c in str])
    padding = ['\\0' for _ in range(0, 4 - (len(str) % 4))] if len(str) % 4 != 0 else []
    return char_array + (", " + ", ".join(padding) + "}") if padding else char_array + "}"


def make_bootloader(ed25519_pub_key, aes_key, hmac_key) -> bool:
    # Change to bootloader directory to build the bootloader from source
    os.chdir(BOOTLOADER_DIR)
    
    # Write the keys to a secret header file
    with open("inc/secrets.h", "w") as f:
        f.write("#define ED25519_PUBLIC_KEY " + padded_char_array(ed25519_pub_key) + "\n")
        f.write("#define AES_KEY " + padded_char_array(aes_key) + "\n")
        f.write("#define HMAC_KEY " + padded_char_array(hmac_key) + "\n")
        
    # Clean current directry to build bootloader 
    subprocess.call("make clean", shell=True)
    status = subprocess.call("make")

    # # Reset the secrets header file
    # with open("inc/secrets.h", "w") as f:
    #     f.write("// No secrets for you :)\n")
    #     f.write("#define ED25519_PUBLIC_KEY \"\"\n")
    #     f.write("#define AES_KEY \"\"\n")
    #     f.write("#define HMAC_KEY \"\"\n")

    # Return True if make returned 0, otherwise return False.
    return status == 0

def save_to_secrets(ed25519_private_key, aes_key, hmac_key):
    #Build bootloader and add Ed25519 public key, AES key, and HMAC key to JSON file
    json_data = {
        "ed25519_private_key": ed25519_private_key,
        "aes_key": aes_key,
        "hmac_key": hmac_key
    }
    os.chdir(os.path.join(BOOTLOADER_DIR,"bin/"))
    with open("secret_build_outputs.json", "w") as f:
        f.write(json.dumps(json_data,indent=4))

if __name__ == "__main__":
    # Generate Ed25519 public and private key and encode in base 64
    ed25519_key = ECC.generate(curve='ed25519')
    ed25519_private_key = base64.b64encode(ed25519_key.export_key(format='PEM').encode('ascii')).decode('ascii')
    ed25519_public_key = base64.b64encode(ed25519_key.public_key().export_key(format='PEM').encode('ascii')).decode('ascii')
    
    # Generate AES and HMAC key and encode in base 64
    aes_key = base64.b64encode(os.urandom(32)).decode('ascii')
    hmac_key = base64.b64encode(os.urandom(32)).decode('ascii')

    # If build successful save keys to secret file 
    if make_bootloader(ed25519_public_key,aes_key,hmac_key):
        save_to_secrets(ed25519_private_key,aes_key,hmac_key)
        print("Bootloader built successfully. Secrets saved.")
    else:
        print("Failed to build bootloader.")
        exit(1)