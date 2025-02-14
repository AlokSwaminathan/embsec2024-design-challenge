#!/usr/bin/env python

# Copyright 2024 The MITRE Corporation. ALL RIGHTS RESERVED
# Approved for public release. Distribution unlimited 23-02181-25.

def get_hex(data):
    hex_string = " ".join(format(byte, "02x") for byte in data)
    return hex_string
