#include "secrets.h"

#include "bootloader.h"
#include "driverlib/eeprom.h"
#include "secret_keys.h"

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
  uint8_t AES_SECRET[] = AES_KEY;
  uint8_t ED25519_SECRET[] = ED25519_PUBLIC_KEY;

  // Write the secrets to EEPROM
  EEPROMProgram((uint32_t*)AES_SECRET, 0, sizeof(AES_SECRET));
  EEPROMProgram((uint32_t*)ED25519_SECRET, sizeof(AES_SECRET), sizeof(ED25519_SECRET));

  // Find the secrets in flash
  bool matches_aes = false;
  bool matches_ed = false;
  uint8_t* aes_flash_addr;
  uint8_t* ed_flash_addr;
  for (uint8_t* addr = 0; (addr < (uint8_t*)0x3FFFF) && (!matches_aes || !matches_ed); addr++) {
    if (!matches_aes && *addr == AES_SECRET[0]) {
      matches_aes = true;
      for (uint8_t* i = addr; i < addr + sizeof(AES_SECRET); i++) {
        if (*i != AES_SECRET[(int)(i - addr)]) {
          matches_aes = false;
          break;
        }
      }
      if (matches_aes) {
        aes_flash_addr = addr;
        addr += sizeof(AES_SECRET);
      }
    } else if (!matches_ed && *addr == ED25519_SECRET[0]) {
      for (uint8_t* i = addr; i < addr + sizeof(ED25519_SECRET); i++) {
        if (*i != ED25519_SECRET[(int)(i - addr)]) {
          matches_ed = false;
          break;
        }
      }
      if (matches_ed) {
        ed_flash_addr = addr;
        addr += sizeof(ED25519_SECRET);
      }
    }
  }

  // Clear the secrets from the stack
  for (int i = 0; i < sizeof(AES_SECRET); i++) {
    AES_SECRET[i] = 0xFF;
  }
  for (int i = 0; i < sizeof(ED25519_SECRET); i++) {
    ED25519_SECRET[i] = 0xFF;
  }

  // Remove the secrets from flash
  int32_t res;
  res = FlashProgram((uint32_t*)AES_SECRET, (uint32_t)aes_flash_addr, sizeof(AES_SECRET));
  res |= FlashProgram((uint32_t*)ED25519_SECRET, (uint32_t)ed_flash_addr, sizeof(ED25519_SECRET));
  if (res != 0) {
    SysCtlReset();
  }
}
#pragma GCC pop_options

uint8_t* read_secrets(void) {
}