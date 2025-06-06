# Add set(CONFIG_USE_driver_enet true) in config.cmake to use this component

include_guard(GLOBAL)
message("${CMAKE_CURRENT_LIST_FILE} component is included.")

if(CONFIG_USE_driver_memory AND (CONFIG_DEVICE_ID STREQUAL MIMX9352xxxxM) AND CONFIG_USE_driver_common)

target_sources(${MCUX_SDK_PROJECT_NAME} PRIVATE
  ${CMAKE_CURRENT_LIST_DIR}/fsl_enet.c
)

target_include_directories(${MCUX_SDK_PROJECT_NAME} PUBLIC
  ${CMAKE_CURRENT_LIST_DIR}/.
)

else()

message(SEND_ERROR "driver_enet.MIMX9352 dependency does not meet, please check ${CMAKE_CURRENT_LIST_FILE}.")

endif()
