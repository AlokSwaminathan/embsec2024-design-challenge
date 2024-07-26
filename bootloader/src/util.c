#include "util.h"

#include "bootloader.h"

/*
 * Program a stream of bytes to the flash.
 * This function takes the starting address of a 1KB page, a pointer to the
 * data to write, and the number of byets to write.
 *
 * This functions performs an erase of the specified flash page before writing
 * the data.
 */
long program_flash(void *page_addr, unsigned char *data, unsigned int data_len) {
  uint32_t word = 0;
  int ret;
  int i;

  // Erase next FLASH page
  FlashErase((uint32_t)page_addr);

  // Clear potentially unused bytes in last word
  // If data not a multiple of 4 (word size), program up to the last word
  // Then create temporary variable to create a full last word
  if (data_len % FLASH_WRITESIZE) {
    // Get number of unused bytes
    int rem = data_len % FLASH_WRITESIZE;
    int num_full_bytes = data_len - rem;

    // Program up to the last word
    ret = FlashProgram((unsigned long *)data, (uint32_t)page_addr, num_full_bytes);
    if (ret != 0) {
      return ret;
    }

    // Create last word variable -- fill unused with 0xFF
    for (i = 0; i < rem; i++) {
      word = (word >> 8) | (data[num_full_bytes + i] << 24);  // Essentially a shift register from MSB->LSB
    }
    for (i = i; i < 4; i++) {
      word = (word >> 8) | 0xFF000000;
    }

    // Program word
    return FlashProgram(&word, (uint32_t)page_addr + num_full_bytes, 4);
  } else {
    // Write full buffer of 4-byte words
    return FlashProgram((unsigned long *)data, (uint32_t)page_addr, data_len);
  }
}

/*
 * Write an unsigned short to the UART.
 */
void uart_write_unsigned_short(uint8_t uart, uint16_t num) {
  // 0 is the execption since it is all 0s
  if (num == 0) {
    uart_write_str(uart, "0");
    return;
  }

  // Longest unsigned short is 5 characters
  char str[6] = "00000";

  // Fill in the string
  int curr = 4;
  while (num > 0) {
    str[curr] = (char)((num % 10) + '0');
    num /= 10;
    curr--;
  }

  // Remove leading zeros
  char *start = str;
  while (*start == '0') {
    start++;
  }

  // Write the string
  uart_write_str(uart, start);
}

 /* Converts arrays bytes into hexadecimal string representation 
 and sends it over UART */

void uart_write_hex_bytes(uint8_t uart, uint8_t *start, uint32_t len) {
  for (uint8_t *cursor = start; cursor < (start + len); cursor += 1) {
    uint8_t data = *((uint8_t *)cursor);
    uint8_t right_nibble = data & 0xF;
    uint8_t left_nibble = (data >> 4) & 0xF;

    char byte_str[3]; // Buffer holds the hexadecimal representation 

   // Convert rigth nibble into ASCII representation
    if (right_nibble > 9) {
      right_nibble += 0x37;
    } else {
      right_nibble += 0x30;
    }

    byte_str[1] = right_nibble;  // Rightmost character in the string

   // Convert left nibble into ASCII representation
    if (left_nibble > 9) {
      left_nibble += 0x37;
    } else {
      left_nibble += 0x30;
    }

    byte_str[0] = left_nibble; // Leftmost character in the string
    byte_str[2] = '\0'; // Null terminator

    uart_write_str(uart, byte_str); // Write the hexadecimal representation to the UART
    uart_write_str(uart, " ");  // Spacing characters
  }
}

void error(uint8_t uart, char *error) {
  uart_write(uart, ERROR);
  uart_write_str(uart, error);
  while (UARTBusy(UART0_BASE)) {
  };
  SysCtlReset();
}

void boot_error(uint8_t uart, char *error) {
  uart_write_str(uart, error);
  while (UARTBusy(UART0_BASE)) {
  };
  SysCtlReset();
}