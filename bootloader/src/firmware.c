#include "firmware.h"

#include "bootloader.h"

// Variables
// Firmware Buffer
unsigned char data[FLASH_PAGESIZE];
uint16_t *fw_version_address;
uint16_t *fw_size_address;
uint8_t *fw_release_message_address;
/*
 * Load the firmware into flash.
 */
void load_firmware(void) {
  int frame_length = 0;
  int read = 0;
  uint32_t rcv = 0;
  uint32_t total_length = 0;

  uint32_t data_index = 0;
  uint32_t page_addr = FW_BASE;

  uint32_t calc_crc = 0;
  uint32_t recv_crc = 0;
  uint8_t framesum[10];

  /* Loop here until you can get all your characters and stuff */
  while (1) {
    // Get two bytes for the length.
    rcv = uart_read(UART0, BLOCKING, &read);
    frame_length = (int)rcv;
    rcv = uart_read(UART0, BLOCKING, &read);
    frame_length += ((int)rcv << 8);

    if (frame_length == 0) {
      uart_write(UART0, DONE);
      while (UARTBusy(UART0_BASE)) {
      };
      break;
    }

    calc_crc = 0xFFFFFFFF;

    // Get the number of bytes specified
    for (int i = 0; i < frame_length; i++) {
      if (data_index >= FLASH_PAGESIZE) {
        int32_t res = program_flash((void *)page_addr, data, data_index);
        if (res != 0) {
          uart_write(UART0, ERROR);
          SysCtlReset();
        }
        page_addr += FLASH_PAGESIZE;
        data_index = 0;
      }
      data[data_index] = uart_read(UART0, BLOCKING, &read);
      calc_crc = Crc32(calc_crc, (uint8_t *)(data + data_index), 1);
      data_index++;
      total_length++;
    }

    for (int i = 0; i < 4; i++) {
      // Use fact that integers are little endian on chip to read recv_crc directly as uint32_t
      ((uint8_t *)&recv_crc)[i] = uart_read(UART0, BLOCKING, &read);
    }

    // Validate recv_crc to ensure data integrity over UART
    if (recv_crc != calc_crc) {
      uart_write(UART0, RESEND);
      while (UARTBusy(UART0_BASE)) {
      };
      // Request a resend
      data_index -= frame_length;  // Remove the frame from the buffer
      if (data_index < 0) {
        data_index = 0;
      }
      total_length -= frame_length;
      continue;
    }

    uart_write(UART0, OK);
    // Acknowledge that frame was successfully received
    while (UARTBusy(UART0_BASE)) {
    };
  }
  // Program leftover frame data to flash
  if (data_index > 0) {
    int32_t res = program_flash((void *)page_addr, data, data_index);
    if (res != 0) {
      uart_write(UART0, ERROR);
      while (UARTBusy(UART0_BASE)) {
      };
      SysCtlReset();
    }
  }

  // TODO : Decrypt the firmware in flash
}

void boot_firmware(void) {
  // Check if firmware loaded
  int fw_present = 0;
  for (uint8_t *i = (uint8_t *)FW_BASE; i < (uint8_t *)FW_BASE + 20; i++) {
    if (*i != 0xFF) {
      fw_present = 1;
    }
  }

  if (!fw_present) {
    uart_write_str(UART0, "No firmware loaded.\n");
    SysCtlReset();  // Reset device
    return;
  }

  // compute the release message address, and then print it
  uint16_t fw_size = *fw_size_address;
  fw_release_message_address = (uint8_t *)(FW_BASE + fw_size);
  uart_write_str(UART0, (char *)fw_release_message_address);

  // Boot the firmware
  __asm(
      "LDR R0,=0x10001\n\t"
      "BX R0\n\t");
}

void decrypt_firmware(uint32_t encrypted_firmware_size) {
}