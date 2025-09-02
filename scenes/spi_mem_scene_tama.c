#include "../spi_mem_app_i.h"
#include "../lib/spi/spi_mem_protection.h"
#include "../lib/spi/spi_mem_tools.h"
#include "../lib/spi/spi_mem_chip_i.h"
#include "../lib/spi/spi_mem_chip.h"
#include "../lib/spi/md5.h"
#include <furi_hal.h>
#include <furi_hal_spi.h>
#include <furi_hal_gpio.h>

typedef enum {
    SPIMemTamaStateUnlock,
    SPIMemTamaStateLock,
} SPIMemTamaState;

static FuriString* str = NULL;

static void spi_mem_scene_tama_widget_callback(
    GuiButtonType result,
    InputType type,
    void* context) {
    SPIMemApp* app = context;
    if(type == InputTypeShort) {
        view_dispatcher_send_custom_event(app->view_dispatcher, result);
    }
}

void spi_mem_scene_tama_on_enter(void* context) {
    SPIMemApp* app = context;
    str = furi_string_alloc();
    widget_add_string_element(
        app->widget, 64, 9, AlignCenter, AlignBottom, FontPrimary, "Tama Reset");
    widget_add_icon_element(app->widget, 5, 15, &I_Dip8_32x36);
    
    furi_string_printf(str, "Vendor id: 0x%02X", spi_mem_chip_get_vendor_id(app->chip_info));
    widget_add_string_multiline_element(
        app->widget, 40, 20, AlignLeft, AlignBottom, FontSecondary, furi_string_get_cstr(str));
    furi_string_printf(str, "Capacity id: 0x%02X", spi_mem_chip_get_capacity_id(app->chip_info));
    widget_add_string_multiline_element(
        app->widget, 40, 34, AlignLeft, AlignBottom, FontSecondary, furi_string_get_cstr(str));
    
    widget_add_button_element(
        app->widget,
        GuiButtonTypeLeft,
        "Back",
        spi_mem_scene_tama_widget_callback,
        app);
    widget_add_button_element(
        app->widget,
        GuiButtonTypeRight,
        "Write",
        spi_mem_scene_tama_widget_callback,
        app);
        
    widget_add_button_element(
        app->widget,
        GuiButtonTypeCenter,
        "Read",
        spi_mem_scene_tama_widget_callback,
        app);

    view_dispatcher_switch_to_view(app->view_dispatcher, SPIMemViewWidget);
}

bool spi_mem_scene_tama_on_event(void* context, SceneManagerEvent event) {
    SPIMemApp* app = context;
    bool success = false;

    if(event.type == SceneManagerEventTypeBack) {
        success = true;
        scene_manager_previous_scene(app->scene_manager);
    } else if(event.type == SceneManagerEventTypeCustom) {
        success = true;
        if(event.event == GuiButtonTypeLeft) {
            scene_manager_previous_scene(app->scene_manager);
        } else if(event.event == GuiButtonTypeCenter) {
            // Read first 16 bytes from address 0x00
            uint32_t address = 0x00;
            uint8_t data[16] = {0};
            bool read_ok = false;

            furi_hal_spi_acquire(&furi_hal_spi_bus_handle_external);
            do {
                uint8_t cmd = (uint8_t)SPIMemChipCMDReadData;
                uint8_t addr_bytes[3];
                addr_bytes[0] = (address >> 16) & 0xFF;
                addr_bytes[1] = (address >> 8) & 0xFF;
                addr_bytes[2] = address & 0xFF;
                furi_hal_gpio_write(&gpio_ext_pa4, false);
                if(!furi_hal_spi_bus_tx(&furi_hal_spi_bus_handle_external, &cmd, 1, SPI_MEM_SPI_TIMEOUT)) break;
                if(!furi_hal_spi_bus_tx(&furi_hal_spi_bus_handle_external, addr_bytes, 3, SPI_MEM_SPI_TIMEOUT)) break;
                if(!furi_hal_spi_bus_rx(&furi_hal_spi_bus_handle_external, data, sizeof(data), SPI_MEM_SPI_TIMEOUT)) break;
                read_ok = true;
            } while(0);
            furi_hal_gpio_write(&gpio_ext_pa4, true);
            furi_hal_spi_release(&furi_hal_spi_bus_handle_external);

            if(read_ok) {
                FURI_LOG_I(TAG, "Tama: Read 16 bytes @0x00 OK: %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X",
                    data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7],
                    data[8], data[9], data[10], data[11], data[12], data[13], data[14], data[15]);
                SPIMemChipStatus status = spi_mem_tools_get_chip_status(app->chip_info);
                FURI_LOG_I(TAG, "Tama: Chip status after read: %d", status);
                scene_manager_search_and_switch_to_another_scene(app->scene_manager, SPIMemSceneStart);
            } else {
                scene_manager_next_scene(app->scene_manager, SPIMemSceneChipError);
            }
        } else if(event.event == GuiButtonTypeRight) {
            // 1) Read first sector (4KB) into header
            const uint32_t sector_addr = 0x000000;
            const size_t sector_size = 0x40; // read/write only first 64 bytes to avoid freezes
            uint8_t header[0x40];
            bool read_sector_ok = false;

            furi_hal_spi_acquire(&furi_hal_spi_bus_handle_external);
            do {
                uint8_t cmd = (uint8_t)SPIMemChipCMDReadData;
                uint8_t ab[3] = {0x00, 0x00, 0x00};
                furi_hal_gpio_write(&gpio_ext_pa4, false);
                if(!furi_hal_spi_bus_tx(&furi_hal_spi_bus_handle_external, &cmd, 1, SPI_MEM_SPI_TIMEOUT)) break;
                if(!furi_hal_spi_bus_tx(&furi_hal_spi_bus_handle_external, ab, 3, SPI_MEM_SPI_TIMEOUT)) break;
                size_t remaining = sector_size;
                uint8_t* ptr = header;
                while(remaining > 0) {
                    size_t chunk = remaining > 256 ? 256 : remaining;
                    if(!furi_hal_spi_bus_rx(&furi_hal_spi_bus_handle_external, ptr, chunk, SPI_MEM_SPI_TIMEOUT)) { remaining = 1; break; }
                    ptr += chunk;
                    remaining -= chunk;
                }
                if(remaining == 0) read_sector_ok = true;
            } while(0);
            furi_hal_gpio_write(&gpio_ext_pa4, true);
            furi_hal_spi_release(&furi_hal_spi_bus_handle_external);

            if(!read_sector_ok) {
                scene_manager_next_scene(app->scene_manager, SPIMemSceneChipError);
                return true;
            }

            // 2) Set header[0x04..0x10] = 0x00
            for(size_t i = 0x04; i <= 0x10; i++) header[i] = 0x00;

            // 3) MD5 over header[0x00..0x3F] (64 bytes)
            MD5Context ctx; md5Init(&ctx); md5Update(&ctx, &header[0x00], 0x40); md5Finalize(&ctx);
            uint8_t digest[16];
            for(size_t i = 0; i < 16; i++) digest[i] = ctx.digest[i];
            FURI_LOG_I(TAG, "Tama: MD5(header 0x00-0x3F) = %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X",
                digest[0], digest[1], digest[2], digest[3], digest[4], digest[5], digest[6], digest[7],
                digest[8], digest[9], digest[10], digest[11], digest[12], digest[13], digest[14], digest[15]);

            // 5) Zero from 0x50 to end of sector: skipped here (we only process 64 bytes header)

            // 6) Erase first sector and write header back page-wise
            bool erase_ok = false;

            furi_hal_spi_acquire(&furi_hal_spi_bus_handle_external);
            do {
                // Write Enable
                uint8_t we = (uint8_t)SPIMemChipCMDWriteEnable;
                furi_hal_gpio_write(&gpio_ext_pa4, false);
                if(!furi_hal_spi_bus_tx(&furi_hal_spi_bus_handle_external, &we, 1, SPI_MEM_SPI_TIMEOUT)) { furi_hal_gpio_write(&gpio_ext_pa4, true); break; }
                furi_hal_gpio_write(&gpio_ext_pa4, true);
                // Sector erase (0x20) + 3-byte address
                uint8_t cmd = 0x20;
                uint8_t addr_bytes[3];
                addr_bytes[0] = (sector_addr >> 16) & 0xFF;
                addr_bytes[1] = (sector_addr >> 8) & 0xFF;
                addr_bytes[2] = sector_addr & 0xFF;
                furi_hal_gpio_write(&gpio_ext_pa4, false);
                if(!furi_hal_spi_bus_tx(&furi_hal_spi_bus_handle_external, &cmd, 1, SPI_MEM_SPI_TIMEOUT)) { furi_hal_gpio_write(&gpio_ext_pa4, true); break; }
                if(!furi_hal_spi_bus_tx(&furi_hal_spi_bus_handle_external, addr_bytes, 3, SPI_MEM_SPI_TIMEOUT)) { furi_hal_gpio_write(&gpio_ext_pa4, true); break; }
                furi_hal_gpio_write(&gpio_ext_pa4, true);
                erase_ok = true;
            } while(0);
            furi_hal_spi_release(&furi_hal_spi_bus_handle_external);

            if(!erase_ok) {
                scene_manager_next_scene(app->scene_manager, SPIMemSceneChipError);
                return true;
            }

            // Wait for erase to complete (WIP clear)
            for(uint32_t i = 0; i < 40000; i++) {
                if(spi_mem_tools_get_chip_status(app->chip_info) == SPIMemChipStatusIdle) break;
                furi_delay_ms(2);
            }
            FURI_LOG_I(TAG, "Tama: Sector erase 4KB (0x20) @0x000000 done");

            // Verify erase: read first 16 bytes should be 0xFF
            bool erased_verified = false;
            uint8_t erased_check[16] = {0};
            furi_hal_spi_acquire(&furi_hal_spi_bus_handle_external);
            do {
                uint8_t rc = (uint8_t)SPIMemChipCMDReadData;
                uint8_t ab[3] = {0x00, 0x00, 0x00};
                furi_hal_gpio_write(&gpio_ext_pa4, false);
                if(!furi_hal_spi_bus_tx(&furi_hal_spi_bus_handle_external, &rc, 1, SPI_MEM_SPI_TIMEOUT)) break;
                if(!furi_hal_spi_bus_tx(&furi_hal_spi_bus_handle_external, ab, 3, SPI_MEM_SPI_TIMEOUT)) break;
                if(!furi_hal_spi_bus_rx(&furi_hal_spi_bus_handle_external, erased_check, sizeof(erased_check), SPI_MEM_SPI_TIMEOUT)) break;
                erased_verified = true;
            } while(0);
            furi_hal_gpio_write(&gpio_ext_pa4, true);
            furi_hal_spi_release(&furi_hal_spi_bus_handle_external);

            bool all_ff = true;
            if(erased_verified) {
                for(size_t i = 0; i < sizeof(erased_check); i++) {
                    if(erased_check[i] != 0xFF) { all_ff = false; break; }
                }
            } else {
                all_ff = false;
            }

            FURI_LOG_I(TAG, "Tama: Erase verify all_ff=%d", all_ff ? 1 : 0);
            
            // If erase not verified, we still proceed to program modified header as per requirement

            // Explicit Write Enable again before program
            furi_hal_spi_acquire(&furi_hal_spi_bus_handle_external);
            do {
                uint8_t we2 = (uint8_t)SPIMemChipCMDWriteEnable;
                if(!furi_hal_spi_bus_tx(&furi_hal_spi_bus_handle_external, &we2, 1, SPI_MEM_SPI_TIMEOUT)) {
                    // fallthrough to write via tools; tools also WREN internally
                }
            } while(0);
            furi_hal_spi_release(&furi_hal_spi_bus_handle_external);

            // Program header back (first 64 bytes)
            size_t page_size = spi_mem_chip_get_page_size(app->chip_info);
            if(page_size == 0 || page_size > SPI_MEM_MAX_BLOCK_SIZE) page_size = SPI_MEM_MAX_BLOCK_SIZE;
            bool write_failed = false;
            {
                size_t to_write = 0x40;
                size_t written = 0;
                while(written < to_write) {
                    size_t chunk = (to_write - written) < page_size ? (to_write - written) : page_size;
                    if(!spi_mem_tools_write_bytes(app->chip_info, (uint32_t)written, &header[written], chunk)) { write_failed = true; break; }
                    for(uint32_t i = 0; i < 2000; i++) {
                        if(spi_mem_tools_get_chip_status(app->chip_info) == SPIMemChipStatusIdle) break;
                        furi_delay_ms(1);
                    }
                    written += chunk;
                }
            }
            if(write_failed) {
                scene_manager_next_scene(app->scene_manager, SPIMemSceneChipError);
                return true;
            }

            // Write digest (16 bytes) to 0x40..0x4F
            if(!spi_mem_tools_write_bytes(app->chip_info, 0x40, digest, 16)) {
                scene_manager_next_scene(app->scene_manager, SPIMemSceneChipError);
                return true;
            }
            for(uint32_t i = 0; i < 2000; i++) {
                if(spi_mem_tools_get_chip_status(app->chip_info) == SPIMemChipStatusIdle) break;
                furi_delay_ms(1);
            }

            // 7) Verify digest area: read 0x40..0x4F (16 bytes)
            uint8_t verify_dig[16] = {0};
            bool v_ok = false;
            furi_hal_spi_acquire(&furi_hal_spi_bus_handle_external);
            do {
                uint8_t rc = (uint8_t)SPIMemChipCMDReadData;
                uint8_t abv[3] = {0x00, 0x00, 0x40};
                furi_hal_gpio_write(&gpio_ext_pa4, false);
                if(!furi_hal_spi_bus_tx(&furi_hal_spi_bus_handle_external, &rc, 1, SPI_MEM_SPI_TIMEOUT)) break;
                if(!furi_hal_spi_bus_tx(&furi_hal_spi_bus_handle_external, abv, 3, SPI_MEM_SPI_TIMEOUT)) break;
                if(!furi_hal_spi_bus_rx(&furi_hal_spi_bus_handle_external, verify_dig, sizeof(verify_dig), SPI_MEM_SPI_TIMEOUT)) break;
                v_ok = true;
            } while(0);
            furi_hal_gpio_write(&gpio_ext_pa4, true);
            furi_hal_spi_release(&furi_hal_spi_bus_handle_external);
            if(v_ok) {
                FURI_LOG_I(TAG, "Tama: Digest @0x40-0x4F: %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X",
                    verify_dig[0], verify_dig[1], verify_dig[2], verify_dig[3], verify_dig[4], verify_dig[5], verify_dig[6], verify_dig[7],
                    verify_dig[8], verify_dig[9], verify_dig[10], verify_dig[11], verify_dig[12], verify_dig[13], verify_dig[14], verify_dig[15]);
            }
            scene_manager_search_and_switch_to_another_scene(app->scene_manager, SPIMemSceneStart);
        }
    }
    return success;
} 

void spi_mem_scene_tama_on_exit(void* context) {
    SPIMemApp* app = context;
    widget_reset(app->widget);
    furi_string_free(str);
}
