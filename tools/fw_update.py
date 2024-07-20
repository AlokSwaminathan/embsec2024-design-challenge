#!/usr/bin/env python

# Copyright 2024 The MITRE Corporation. ALL RIGHTS RESERVED
# Approved for public release. Distribution unlimited 23-02181-25.

"""
Firmware Updater Tool

A frame consists of three sections:
1. Two bytes for the length of the data section (little endian)
2. A data section of length defined in the length section
3. A two byte CRC16 checksum of the data section

[ 0x02 ]  [ variable ] [crc32]
-------------------------------
| Length | Data... | Checksum |
--------------------------------

In our case, the data is from one line of the Intel Hex formated .hex file

We write a frame to the bootloader, then wait for it to respond with an
OK message so we can write the next frame. The OK message in this case is
just a 0
If the bootloader responds with a 1, then we resend the message
If the bootloader responds with a 2, then we are done writing the firmware
If the bootloader responds with a 3, there has been an error and we should stop writing firmware
"""

import argparse
from pwn import *
import time
import serial
import platform

from util import *

if platform.system() == 'Darwin':
    ser = serial.Serial("/dev/tty.usbmodem0E23AD551", 115200)
else:
    ser = serial.Serial("/dev/ttyACM0", 115200)

RESP_OK = b"\x00"
RESP_RESEND = b"\x01"
RESP_DONE = b"\x02"
RESP_ERROR = b"\x03"
FRAME_SIZE = 256


def send_frame(ser, frame, debug=False):
    ser.write(frame)  # Write the frame...

    if debug:
        print_hex(frame)

    resp = ser.read(1)  # Wait for an OK from the bootloader

    time.sleep(0.1)

    if debug:
        print("Resp: {}".format(ord(resp)))
    
    if resp == RESP_ERROR:
        raise RuntimeError(
            "ERROR: Bootloader responded with {}".format(repr(resp)))
    elif resp == RESP_RESEND:
        if debug:
            print("Resending frame")
        send_frame(ser, frame, debug=debug)


def update(ser, infile, debug):
    # Open serial port. Set baudrate to 115200. Set timeout to 2 seconds.
    with open(infile, "rb") as fp:

    for idx, frame_start in enumerate(range(0, len(firmware), FRAME_SIZE)):
        data = firmware[frame_start: frame_start + FRAME_SIZE]

        # Construct frame.
        frame = p16(len(data), endian='big') + data

        send_frame(ser, frame, debug=debug)
        print(f"Wrote frame {idx} ({len(frame)} bytes)")
        firmware = fp.read()

    print("Done writing firmware.")

    # Send a zero length payload to tell the bootlader to finish writing it's page.
    ser.write(p16(0x0000, endian='big'))
    resp = ser.read(1)  # Wait for an OK from the bootloader
    if resp != RESP_OK:
        raise RuntimeError(
            "ERROR: Bootloader responded to zero length frame with {}".format(repr(resp)))
    print(f"Wrote zero length frame (2 bytes)")

    return ser


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Firmware Update Tool")

    parser.add_argument(
        "--firmware", help="Path to firmware image to load.", required=True)
    parser.add_argument(
        "--debug", help="Enable debugging messages.", action="store_true")
    args = parser.parse_args()

    update(ser=ser, infile=args.firmware, debug=args.debug)
    ser.close()
