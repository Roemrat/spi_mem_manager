#include "../spi_mem_app_i.h"
#include "../lib/spi/spi_mem_protection.h"

typedef enum {
    SPIMemProtectStateUnlock,
    SPIMemProtectStateLock,
} SPIMemProtectState;

static FuriString* str = NULL;

static void spi_mem_scene_protect_widget_callback(
    GuiButtonType result,
    InputType type,
    void* context) {
    SPIMemApp* app = context;
    if(type == InputTypeShort) {
        view_dispatcher_send_custom_event(app->view_dispatcher, result);
    }
}

void spi_mem_scene_protect_on_enter(void* context) {
    SPIMemApp* app = context;
    str = furi_string_alloc();
    widget_add_string_element(
        app->widget, 64, 9, AlignCenter, AlignBottom, FontPrimary, "SPI Write Protection");
    widget_add_icon_element(app->widget, 5, 15, &I_Dip8_32x36);
    
    furi_string_printf(str, "Vendor id: 0x%02X", spi_mem_chip_get_vendor_id(app->chip_info));
    widget_add_string_multiline_element(
        app->widget, 40, 30, AlignLeft, AlignBottom, FontSecondary, furi_string_get_cstr(str));
    furi_string_printf(str, "Capacity id: 0x%02X", spi_mem_chip_get_capacity_id(app->chip_info));
    widget_add_string_multiline_element(
        app->widget, 40, 44, AlignLeft, AlignBottom, FontSecondary, furi_string_get_cstr(str));
        
    widget_add_button_element(
        app->widget,
        GuiButtonTypeLeft,
        "Lock",
        spi_mem_scene_protect_widget_callback,
        app);
    widget_add_button_element(
        app->widget,
        GuiButtonTypeRight,
        "Unlock",
        spi_mem_scene_protect_widget_callback,
        app);
    view_dispatcher_switch_to_view(app->view_dispatcher, SPIMemViewWidget);
}

bool spi_mem_scene_protect_on_event(void* context, SceneManagerEvent event) {
    SPIMemApp* app = context;
    bool success = false;

    if(event.type == SceneManagerEventTypeBack) {
        success = true;
        scene_manager_previous_scene(app->scene_manager);
    } else if(event.type == SceneManagerEventTypeCustom) {
        success = true;
        if(event.event == GuiButtonTypeLeft) {
            app->protect_state = SPIMemProtectStateLock;
            bool success = false;
            // Check for specific chip (vendor 0xC2, capacity 0x14)
            if(spi_mem_chip_get_vendor_id(app->chip_info) == 0xC2 && 
               spi_mem_chip_get_capacity_id(app->chip_info) == 0x14) {
                success = spi_mem_protection_lock_xc2x14(app->chip_info);
            } else {
                success = spi_mem_protection_lock(app->chip_info);
            }
            if(success) {
                scene_manager_next_scene(app->scene_manager, SPIMemSceneSuccess);
            } else {
                scene_manager_next_scene(app->scene_manager, SPIMemSceneChipError);
            }
        } else if(event.event == GuiButtonTypeRight) {
            app->protect_state = SPIMemProtectStateUnlock;
            if(spi_mem_protection_unlock(app->chip_info)) {
                scene_manager_next_scene(app->scene_manager, SPIMemSceneSuccess);
            } else {
                scene_manager_next_scene(app->scene_manager, SPIMemSceneChipError);
            }
        }
    }
    return success;
}

void spi_mem_scene_protect_on_exit(void* context) {
    SPIMemApp* app = context;
    widget_reset(app->widget);
    furi_string_free(str); // Free the string we allocated
}
