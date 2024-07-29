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

# Define bootloader binary padding
TARGET_SIZE = 256 * 1024
VERSION_OFFSET = 0x3FC00
DEFAULT_VERSION = b'\x00\x00'

# Pad binary to 256kb so all flash is under control
# Then set the start of the last block to store a firmware version of 0x0000
def pad_bootloader_binary() -> None:
  file_path = 'bin/bootloader.bin'
  with open(file_path, "rb+") as bootloader:
    current_size = os.path.getsize(file_path)
    bytes_left = TARGET_SIZE - current_size
    
    if bytes_left > 0:
      bootloader.seek(0,os.SEEK_END)
      bootloader.write(b'\xFF' * bytes_left)

    bootloader.seek(VERSION_OFFSET)
    bootloader.write(DEFAULT_VERSION)

# Formats a key into C style array and pads it to 4 bytes 
def padded_uint8t_array(key: bytes) -> str:
    char_array = "{" + ", ".join([f"0x{b:02x}" for b in key])
    padding = ['0x00' for _ in range(0, 4 - (len(key) % 4))] if len(key) % 4 != 0 else []
    return char_array + (", " + ", ".join(padding) + "}") if padding else char_array + "}"

def make_bootloader(ed25519_pub_key: bytes, aes_key: bytes) -> bool:
    # Change to bootloader directory to build the bootloader from source
    os.chdir(BOOTLOADER_DIR)

    # Write the keys to a secret header file
    with open("inc/secret_keys.h", "w") as secrets_header:
        secrets_header.write("#define ED25519_PUBLIC_KEY " + padded_uint8t_array(ed25519_pub_key) + "\n")
        secrets_header.write("#define ED25519_PUBLIC_KEY_SIZE " + str(len(ed25519_pub_key)) + "\n")
        secrets_header.write("#define AES_KEY " + padded_uint8t_array(aes_key) + "\n")
        secrets_header.write("#define AES_KEY_SIZE " + str(len(aes_key)) + "\n")

    # Clean current directory to build bootloader
    subprocess.call("make clean", shell=True)
    status = subprocess.call("make")

    if status != 0:
        return False
    
    # Reset the secrets header file
    with open("inc/secret_keys.h", "w") as secrets_header:
        secrets_header.write("// No secrets for you :)\n")
        secrets_header.write("#define ED25519_PUBLIC_KEY {}\n")
        secrets_header.write("#define ED25519_PUBLIC_KEY_SIZE 0\n")
        secrets_header.write("#define AES_KEY {}\n")
        secrets_header.write("#define AES_KEY_SIZE 0\n")

    pad_bootloader_binary()

    # Return True if make returned 0, otherwise return False.
    return status == 0

def save_to_secrets(ed25519_private_key: bytes,ed25519_public_key: bytes, aes_key: bytes) -> None:
    # Build bootloader and add Ed25519 private key and AES key to JSON file
    json_data = {
        "ed25519_private_key": ed25519_private_key,
        "aes_key": aes_key
    }
    os.chdir(REPO_ROOT)
    with open("secret_build_output.txt", "w") as f:
        json.dump(json_data, f, indent=4)

if __name__ == "__main__":
    # Generate Ed25519 keys and encode in base64 if needed
    ed25519_key = ECC.generate(curve='ed25519')
    ed25519_private_key_b64 = base64.b64encode(ed25519_key.export_key(format='PEM').encode('ascii')).decode('ascii')
    ed25519_public_key_b64 = base64.b64encode(ed25519_key.public_key().export_key(format='PEM').encode('ascii')).decode('ascii')
    ed25519_public_key_raw: bytes = ed25519_key.public_key().export_key(format='raw')

    # Generate AES key and encode in base64
    aes_key = os.urandom(32)
    aes_key_b64 = base64.b64encode(aes_key).decode('ascii')

    # If build successful, save keys to secret file
    if make_bootloader(ed25519_public_key_raw, aes_key):
        save_to_secrets(ed25519_private_key_b64, ed25519_public_key_b64, aes_key_b64)
        print("Bootloader built successfully. Secrets saved.")
    else:
        print("Failed to build bootloader.")
        exit(1)
