#ifndef FIRMWARE_H
#define FIRMWARE_H

#include "stdint.h"

// Function stubs
void load_firmware(void);
void boot_firmware(void);
void decrypt_firmware(uint32_t encrypted_firmware_size);

#endif