#ifndef UTIL_H
#define UTIL_H

#include <stdint.h>

long program_flash(void* page_addr, unsigned char* data, unsigned int data_len);
void uart_write_hex_bytes(uint8_t, uint8_t*, uint32_t);
void uart_write_unsigned_short(uint8_t, uint16_t);
void error(uint8_t uart, char* error);
void boot_error(uint8_t uart, char* error);
#endif