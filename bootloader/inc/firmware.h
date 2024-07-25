#ifndef FIRMWARE_H
#define FIRMWARE_H

#include "stdint.h"
#include "stdbool.h"

uint32_t load_firmware(void);
void boot_firmware(void);
void decrypt_firmware(uint32_t);
void verify_firmware(uint32_t);
void check_firmware_version(void);
void set_firmware_metadata(uint32_t);
void finalize_firmware(void);

#endif