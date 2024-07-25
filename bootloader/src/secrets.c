#include "secrets.h"

#include "bootloader.h"
#include "driverlib/eeprom.h"
#include "secret_keys.h"

void remove_secret(volatile uint8_t*, uint32_t);

// Global Variables
extern uint8_t data[FLASH_PAGESIZE];

/*
 * Write secrets to EEPROM
 */
#pragma GCC push_options
#pragma GCC optimize("O0")
void write_and_remove_secrets(void) {
  // Enable and wait for EEPROM to be ready
  SysCtlPeripheralEnable(SYSCTL_PERIPH_EEPROM0);
  while (!SysCtlPeripheralReady(SYSCTL_PERIPH_EEPROM0)) {
  }

  // Unlock the EEPROM
  uint32_t EEPROMInitRes = EEPROMInit();

  if (EEPROMInitRes != EEPROM_INIT_OK) {
    SysCtlReset();
  }

  // Get keys from secrets.h
  volatile uint8_t AES_SECRET[] = AES_KEY;
  volatile uint8_t ED25519_SECRET[] = ED25519_PUBLIC_KEY;

  bool secrets_valid = false;
  for (int i = 0; i < AES_KEY_SIZE; i++) {
    if (AES_SECRET[i] != 0xFF) {
      secrets_valid = true;
      break;
    }
  }
  for (int i = 0; i < ED25519_PUBLIC_KEY_SIZE; i++) {
    if (ED25519_SECRET[i] != 0xFF) {
      secrets_valid = true;
      break;
    }
  }
  if (!secrets_valid) {
    return;
  }

  // Write the secrets to EEPROM
  EEPROMProgram((uint32_t*)AES_SECRET, AES_KEY_EEPROM_ADDR, AES_KEY_SIZE);
  EEPROMProgram((uint32_t*)ED25519_SECRET,ED25519_PUBLIC_KEY_EEPROM_ADDR, ED25519_PUBLIC_KEY_SIZE);

  // Remove secrets from flash and stack
  remove_secret(AES_SECRET, AES_KEY_SIZE);
  remove_secret(ED25519_SECRET, ED25519_PUBLIC_KEY_SIZE);

  SysCtlReset();
}
#pragma GCC pop_options

// Remove individual secrets from flash
#pragma GCC push_options
#pragma GCC optimize("O0")
void remove_secret(volatile uint8_t* secret, uint32_t size) {
  // Find the secret in flash
  bool matches = false;
  uint8_t* flash_addr;
  for (uint8_t* addr = 0; (addr < (uint8_t*)0x3FFFF) && !matches; addr++) {
    if (*addr == secret[0]) {
      matches = true;
      for (uint8_t* i = addr; i < addr + size; i++) {
        if (*i != secret[(int)(i - addr)]) {
          matches = false;
          break;
        }
      }
      if (matches) {
        flash_addr = addr;
        addr += size;
      }
    }
  }

  // Clear the secret from the stack
  for (int i = 0; i < size; i++) {
    secret[i] = 0xFF;
  }

  // Clear the secret from flash
  int32_t res;
  uint32_t block_addr = (uint32_t)flash_addr - ((uint32_t)flash_addr % FLASH_PAGESIZE);
  for (uint32_t i = 0; i < FLASH_PAGESIZE; i++) {
    if (block_addr + i >= (uint32_t)flash_addr && block_addr + i < (uint32_t)flash_addr + size) {
        data[i] = 0xFF;
      } else {
        data[i] = *((uint8_t*)(block_addr + i));
      }
  }
  res = program_flash((void*)block_addr, data, FLASH_PAGESIZE);
  if (res != 0) {
    SysCtlReset();
  }
  if ((uint32_t)flash_addr + size > block_addr + FLASH_PAGESIZE) {
    block_addr += FLASH_PAGESIZE;
    for (uint32_t i = 0; i < FLASH_PAGESIZE; i++) {
      if (block_addr + i < (uint32_t)flash_addr + size) {
        data[i] = 0xFF;
      } else {
        data[i] = *((uint8_t*)(block_addr + i));
      }
    }
    res = program_flash((void*)block_addr, data, FLASH_PAGESIZE);
    if (res != 0) {
      SysCtlReset();
    }
  }
}
#pragma GCC pop_options