# Add set(CONFIG_USE_utility_debug_console_lite true) in config.cmake to use this component

include_guard(GLOBAL)
message("${CMAKE_CURRENT_LIST_FILE} component is included.")

if(CONFIG_USE_component_lpuart_adapter AND (CONFIG_DEVICE_ID STREQUAL MIMX9352xxxxM) AND CONFIG_USE_driver_common AND CONFIG_USE_utility_str)

target_sources(${MCUX_SDK_PROJECT_NAME} PRIVATE
  ${CMAKE_CURRENT_LIST_DIR}/debug_console_lite/fsl_debug_console.c
)

target_include_directories(${MCUX_SDK_PROJECT_NAME} PUBLIC
  ${CMAKE_CURRENT_LIST_DIR}/debug_console_lite
)

else()

message(SEND_ERROR "utility_debug_console_lite.MIMX9352 dependency does not meet, please check ${CMAKE_CURRENT_LIST_FILE}.")

endif()
