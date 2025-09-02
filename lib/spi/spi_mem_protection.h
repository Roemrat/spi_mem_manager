#pragma once

#include "spi_mem_chip.h"

// SPI Flash standard commands for status register operations
#define SPI_FLASH_CMD_RDSR 0x05 // Read Status Register
#define SPI_FLASH_CMD_WRSR 0x01 // Write Status Register
#define SPI_FLASH_CMD_WREN 0x06 // Write Enable
#define SPI_FLASH_CMD_WRDI 0x04 // Write Disable

// Status Register bit definitions
#define SPI_FLASH_SREG_WIP (0x01 << 0) // Write in progress
#define SPI_FLASH_SREG_WEL (0x01 << 1) // Write enable latch
#define SPI_FLASH_SREG_BP0 (0x01 << 2) // Block protect 0
#define SPI_FLASH_SREG_BP1 (0x01 << 3) // Block protect 1
#define SPI_FLASH_SREG_BP2 (0x01 << 4) // Block protect 2
#define SPI_FLASH_SREG_TB (0x01 << 5) // Top/Bottom protect
#define SPI_FLASH_SREG_SEC (0x01 << 6) // Sector protect
#define SPI_FLASH_SREG_WRITE_PROTECT (0x01 << 7) // Write protect bit

// Function declarations
bool spi_mem_protection_unlock(SPIMemChip* chip);
bool spi_mem_protection_lock(SPIMemChip* chip);
bool spi_mem_protection_lock_xc2x14(SPIMemChip* chip);
uint8_t spi_mem_protection_get_status(SPIMemChip* chip);
