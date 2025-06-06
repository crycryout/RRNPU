# Add set(CONFIG_USE_middleware_lwip_apps_httpd_support true) in config.cmake to use this component

include_guard(GLOBAL)
message("${CMAKE_CURRENT_LIST_FILE} component is included.")

if(CONFIG_USE_middleware_lwip)

target_sources(${MCUX_SDK_PROJECT_NAME} PRIVATE
  ${CMAKE_CURRENT_LIST_DIR}/src/apps/http/fs.c
)

target_include_directories(${MCUX_SDK_PROJECT_NAME} PUBLIC
  ${CMAKE_CURRENT_LIST_DIR}/src/apps/http
  ${CMAKE_CURRENT_LIST_DIR}/src/include/lwip/apps
)

else()

message(SEND_ERROR "middleware_lwip_apps_httpd_support dependency does not meet, please check ${CMAKE_CURRENT_LIST_FILE}.")

endif()
