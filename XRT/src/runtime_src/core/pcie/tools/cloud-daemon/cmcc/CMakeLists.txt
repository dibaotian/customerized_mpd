if (NOT ${CMAKE_SYSTEM_PROCESSOR} MATCHES "arm")

include_directories(
  ${CMAKE_CURRENT_SOURCE_DIR}
  )

file(GLOB CMCC_PLUGIN_FILES
  "cmcc.h"
  "cmcc.cpp"
  "../common.h"
  "../common.cpp"
  "../sw_msg.h"
  "../sw_msg.cpp"
  "../pciefunc.h"
  "../pciefunc.cpp"
  )

add_library(cmcc_plugin OBJECT ${CMCC_PLUGIN_FILES})

add_library(cmcc_mpd_plugin SHARED ""
  $<TARGET_OBJECTS:cmcc_plugin>
)

add_compile_options("-fPIC")

target_link_libraries(cmcc_mpd_plugin
  xrt_core_static
  xrt_coreutil_static
  uuid
  boost_filesystem
  boost_system
  pthread
  rt
  dl
  curl
  crypto
  )

install(TARGETS cmcc_mpd_plugin
  LIBRARY
  DESTINATION ${XRT_INSTALL_DIR}/lib
  COMPONENT cmcc
  )

endif (NOT ${CMAKE_SYSTEM_PROCESSOR} MATCHES "arm")
