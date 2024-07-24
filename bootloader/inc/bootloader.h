// Copyright 2024 The MITRE Corporation. ALL RIGHTS RESERVED
// Approved for public release. Distribution unlimited 23-02181-25.

#ifndef BOOTLOADER_H
#define BOOTLOADER_H

#include <stdbool.h>
#include <stdint.h>
#include <string.h>

// Hardware Imports
#include "inc/hw_memmap.h"     // Peripheral Base Addresses
#include "inc/hw_types.h"      // Boolean type
#include "inc/tm4c123gh6pm.h"  // Peripheral Bit Masks and Registers
// #include "inc/hw_ints.h" // Interrupt numbers

// Driver API Imports
#include "driverlib/flash.h"      // FLASH API
#include "driverlib/interrupt.h"  // Interrupt API
#include "driverlib/sysctl.h"     // System control API (clock/reset)

// Application Imports
#include "driverlib/gpio.h"
#include "driverlib/uart.h"
#include "uart/uart.h"

// Cryptography Imports
#include "wolfssl/wolfcrypt/aes.h"
#include "wolfssl/wolfcrypt/rsa.h"
#include "wolfssl/wolfcrypt/settings.h"
#include "wolfssl/wolfcrypt/sha.h"

// Checksum Imports
#include "driverlib/sw_crc.h"

#define IV_LEN 16
#define MAX_MSG_LEN 256

// Firmware Constants
#define METADATA_BASE 0x3FC00  // base address of version and firmware size in Flash
#define FW_BASE 0x20000       // base address of firmware in Flash

// FLASH Constants
#define FLASH_PAGESIZE 1024
#define FLASH_WRITESIZE 4

// Protocol Constants
#define OK ((unsigned char)0x00)
#define RESEND ((unsigned char)0x01)
#define DONE ((unsigned char)0x02)
#define ERROR ((unsigned char)0x03)

#define UPDATE ((unsigned char)'U')
#define BOOT ((unsigned char)'B')

// Data buffer sizes
#define META_LEN 22 // Excludes message bytes
#define IV_LEN 16
#define MAX_MSG_LEN 256
#define BLOCK_SIZE FLASH_PAGESIZE
#define SIG_SIZE 256
#define CHUNK_SIZE (BLOCK_SIZE + SIG_SIZE)

#define MAX_CHUNK_NO 32 // 30KB firmware + padding

// Return messages
#define VERIFY_SUCCESS 0
#define VERIFY_ERR 1

#define FW_LOADED 0
#define FW_ERROR 1

#define FW_VERSION_ADDR (uint16_t*)0x3FC00
#define FW_SIZE_ADDR (uint16_t*)0x20002


typedef struct fw_meta_s {
    uint16_t    ver;                // Version of current fw being loaded
    uint16_t    min_ver;            // Miniumum fw version (not updated when debug fw loaded) 
    uint16_t    chunks;             // Length of fw in 1kb chunks
    uint16_t    msgLen;             // Length of fw message in bytes
    uint8_t     msg[MAX_MSG_LEN];   // fw release message
} fw_meta_st;

long program_flash(void* page_addr, unsigned char * data, unsigned int data_len);

#endif

