# Add set(CONFIG_USE_driver_nand_flash-controller-flexspi true) in config.cmake to use this component

include_guard(GLOBAL)
message("${CMAKE_CURRENT_LIST_FILE} component is included.")

if(CONFIG_USE_driver_nand_flash-common AND CONFIG_USE_driver_flexspi)

target_sources(${MCUX_SDK_PROJECT_NAME} PRIVATE
  ${CMAKE_CURRENT_LIST_DIR}/fsl_flexspi_nand_flash.c
)

target_include_directories(${MCUX_SDK_PROJECT_NAME} PUBLIC
  ${CMAKE_CURRENT_LIST_DIR}/.
)

else()

message(SEND_ERROR "driver_nand_flash-controller-flexspi.MIMX9352 dependency does not meet, please check ${CMAKE_CURRENT_LIST_FILE}.")

endif()
