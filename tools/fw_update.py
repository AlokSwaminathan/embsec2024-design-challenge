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
import time
import serial
import platform
from zlib import crc32

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
    ser.write(p16(len(frame), endian='little'))  # Write the frame length
    
    ser.write(frame)  # Write the frame data
    
    checksum = p32(crc32(frame),endian='little')
    
    ser.write(checksum)  # Write the frame checksum

    if debug:
        print_hex(frame)

    resp = ser.read(1)  # Wait for an OK from the bootloader

    # Tenatively keep this line, idk why its here though
    time.sleep(0.1)

        # Check if debugging is enabled
    if debug:
        print("Resp: {}".format(ord(resp)))

    # Handle the received response
    if resp == RESP_ERROR:
        raise RuntimeError(
            "ERROR: Bootloader responded with {}".format(repr(resp)))
    elif resp == RESP_RESEND:
        if debug:
            print("Resending frame")
        # Call the function to resend the frame
        send_frame(ser, frame, debug=debug)


def update(ser, infile, debug):
    # Open serial port. Set baudrate to 115200. Set timeout to 2 seconds.
    with open(infile, "rb") as fp:
        firmware = fp.read()

    # Send firmware in frames
    num_frames = len(firmware) // FRAME_SIZE
    num_frames -= 1 if len(firmware) % FRAME_SIZE == 0 else 0
    for i in range(0, len(firmware), FRAME_SIZE):
        frame = firmware[i:i+FRAME_SIZE]
        send_frame(ser, frame,debug=debug)
        print(f"Sent frame {i//FRAME_SIZE} of {len(firmware)//FRAME_SIZE}")
    

    print("Done writing firmware.")

    # Send a zero length payload to tell the bootlader to finish writing it's page.
    ser.write(p16(0x0000, endian='little'))
    resp = ser.read(1)  # Wait for a DONE from the bootloader
    if resp != RESP_DONE:
        raise RuntimeError(
            "ERROR: Bootloader responded to zero length frame with {}".format(repr(resp)))
    print(f"Wrote zero length frame (2 bytes) and finished writing firmware")

    return ser
import argparse

if __name__ == "__main__":
    # Create an argument parser for command line arguments
    parser = argparse.ArgumentParser(description="Firmware Update Tool")

    parser.add_argument(
        "--firmware", help="Path to firmware image to load.", required=True)
    
    parser.add_argument(
        "--debug", help="Enable debugging messages.", action="store_true")
    
    # Parse the command line arguments
    args = parser.parse_args()

    # Call the update function with the parsed arguments
    update(ser=ser, infile=args.firmware, debug=args.debug)
    
    ser.close()
