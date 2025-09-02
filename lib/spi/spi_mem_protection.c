#include "spi_mem_protection.h"
#include "spi_mem_chip_i.h"
#include <furi_hal.h>
#include <furi_hal_spi.h>
#include <furi_hal_gpio.h>

static void spi_mem_cs_low() {
    furi_hal_gpio_write(&gpio_ext_pa4, false);
}

static void spi_mem_cs_high() {
    furi_hal_gpio_write(&gpio_ext_pa4, true);
}

static bool spi_mem_protection_write_enable(SPIMemChip* chip) {
    UNUSED(chip);
    uint8_t cmd = SPI_FLASH_CMD_WREN;
    furi_hal_spi_acquire(&furi_hal_spi_bus_handle_external);
    spi_mem_cs_low();
    furi_hal_spi_bus_tx(&furi_hal_spi_bus_handle_external, &cmd, 1, 100);
    spi_mem_cs_high();
    furi_hal_spi_release(&furi_hal_spi_bus_handle_external);
    return true;
}

static bool spi_mem_protection_wait_busy(SPIMemChip* chip) {
    UNUSED(chip);
    uint8_t status;
    do {
        status = spi_mem_protection_get_status(chip);
    } while(status & SPI_FLASH_SREG_WIP);
    return true;
}

uint8_t spi_mem_protection_get_status(SPIMemChip* chip) {
    UNUSED(chip);
    uint8_t cmd = SPI_FLASH_CMD_RDSR;
    uint8_t status = 0;
    
    furi_hal_spi_acquire(&furi_hal_spi_bus_handle_external);
    spi_mem_cs_low();
    furi_hal_spi_bus_tx(&furi_hal_spi_bus_handle_external, &cmd, 1, 100);
    furi_hal_spi_bus_rx(&furi_hal_spi_bus_handle_external, &status, 1, 100);
    spi_mem_cs_high();
    furi_hal_spi_release(&furi_hal_spi_bus_handle_external);
    
    return status;
}

bool spi_mem_protection_unlock(SPIMemChip* chip) {
    UNUSED(chip);
    uint8_t cmd[2] = {SPI_FLASH_CMD_WRSR, 0x00}; // Clear all protection bits
    
    // Enable writes first
    if(!spi_mem_protection_write_enable(chip)) return false;
    
    // Write status register
    furi_hal_spi_acquire(&furi_hal_spi_bus_handle_external);
    furi_hal_gpio_write(&gpio_ext_pa4, false);
    furi_hal_spi_bus_tx(&furi_hal_spi_bus_handle_external, cmd, 2, 100);
    furi_hal_gpio_write(&gpio_ext_pa4, true);
    furi_hal_spi_release(&furi_hal_spi_bus_handle_external);
    
    // Wait for write to complete
    spi_mem_protection_wait_busy(chip);
    
    // Verify status
    uint8_t status = spi_mem_protection_get_status(chip);
    return (status & (SPI_FLASH_SREG_WRITE_PROTECT | SPI_FLASH_SREG_BP2 | SPI_FLASH_SREG_BP1 | SPI_FLASH_SREG_BP0)) == 0;
}

bool spi_mem_protection_lock(SPIMemChip* chip) {
    UNUSED(chip);
    uint8_t cmd[2] = {SPI_FLASH_CMD_WRSR, SPI_FLASH_SREG_WRITE_PROTECT | SPI_FLASH_SREG_BP2 | SPI_FLASH_SREG_BP1 | SPI_FLASH_SREG_BP0 | SPI_FLASH_SREG_TB | SPI_FLASH_SREG_SEC}; // Set all protection bits
    
    // Enable writes first
    if(!spi_mem_protection_write_enable(chip)) return false;
    
    // Write status register
    furi_hal_spi_acquire(&furi_hal_spi_bus_handle_external);
    furi_hal_gpio_write(&gpio_ext_pa4, false);
    furi_hal_spi_bus_tx(&furi_hal_spi_bus_handle_external, cmd, 2, 100);
    furi_hal_gpio_write(&gpio_ext_pa4, true);
    furi_hal_spi_release(&furi_hal_spi_bus_handle_external);
    
    // Wait for write to complete
    spi_mem_protection_wait_busy(chip);
    
    // Verify status
    uint8_t status = spi_mem_protection_get_status(chip);
    return (status & (SPI_FLASH_SREG_WRITE_PROTECT | SPI_FLASH_SREG_BP2 | SPI_FLASH_SREG_BP1 | SPI_FLASH_SREG_BP0)) != 0;
}

bool spi_mem_protection_lock_xc2x14(SPIMemChip* chip) {
    UNUSED(chip);
    uint8_t cmd[2] = {SPI_FLASH_CMD_WRSR, SPI_FLASH_SREG_WRITE_PROTECT | SPI_FLASH_SREG_BP2 | SPI_FLASH_SREG_BP1 | SPI_FLASH_SREG_BP0 }; // Set all protection bits
    
    // Enable writes first
    if(!spi_mem_protection_write_enable(chip)) return false;
    
    // Write status register
    furi_hal_spi_acquire(&furi_hal_spi_bus_handle_external);
    furi_hal_gpio_write(&gpio_ext_pa4, false);
    furi_hal_spi_bus_tx(&furi_hal_spi_bus_handle_external, cmd, 2, 100);
    furi_hal_gpio_write(&gpio_ext_pa4, true);
    furi_hal_spi_release(&furi_hal_spi_bus_handle_external);
    
    // Wait for write to complete
    spi_mem_protection_wait_busy(chip);
    
    // Verify status
    uint8_t status = spi_mem_protection_get_status(chip);
    return (status & (SPI_FLASH_SREG_WRITE_PROTECT | SPI_FLASH_SREG_BP2 | SPI_FLASH_SREG_BP1 | SPI_FLASH_SREG_BP0)) != 0;
}
