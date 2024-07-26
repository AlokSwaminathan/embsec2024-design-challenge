#ifndef FIRMWARE_H
#define FIRMWARE_H

#include "stdbool.h"
#include "stdint.h"

void load_firmware(void);
void boot_firmware(void);
void decrypt_firmware(void);
void verify_firmware(void);
void check_firmware_version(void);
void set_firmware_metadata(void);
void finalize_firmware(void);
bool pre_boot_verify_firmware(void);

// Firmware Constants
#define METADATA_BASE 0x3FC00  // base address of version and firmware size in Flash
#define FW_TEMP_BASE 0x30000   // temporary firmware storage location
#define FW_BASE 0x20000        // final firmware storage location

#define FW_VERSION_LEN 2
#define FW_SIZE_LEN 2
#define INITIAL_METADATA_LEN 4
#define FW_SIG_LEN 64

#define FW_TEMP_VERSION_ADDR 0x30000
#define FW_TEMP_SIZE_ADDR 0x30002
#define FW_TEMP_RELEASE_MSG_ADDR (FW_TEMP_SIZE_ADDR + FW_SIZE_LEN + *((uint16_t *)(FW_TEMP_SIZE_ADDR)))

#define FW_VERSION_ADDR 0x3FC00
#define FW_SIZE_ADDR (FW_VERSION_ADDR + FW_VERSION_LEN)
#define FW_RELEASE_MSG_ADDR (FW_SIZE_ADDR + FW_SIZE_LEN)
#define FW_SIG_ADDR 0x3FF00
#define FW_DEBUG_ADDR 0x3FFFF
#define __FW_IS_DEBUG ((*((uint8_t *)FW_DEBUG_ADDR) & 0x01) == 0x0)

#define DEBUG_BYTE 0xFE
#define DEFAULT_BYTE 0xFF

#endif