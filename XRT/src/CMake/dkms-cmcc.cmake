
set(DKMS_FILE_NAME "dkms-cmcc.conf")
set(DKMS_POSTINST "postinst-cmcc")
set(DKMS_PRERM "prerm-cmcc")

configure_file(
  "${CMAKE_SOURCE_DIR}/CMake/config/${DKMS_FILE_NAME}.in"
  "cmcc/${DKMS_FILE_NAME}"
  @ONLY
  )

configure_file(
  "${CMAKE_SOURCE_DIR}/CMake/config/${DKMS_POSTINST}.in"
  "cmcc/postinst"
  @ONLY
  )

configure_file(
  "${CMAKE_SOURCE_DIR}/CMake/config/${DKMS_PRERM}.in"
  "cmcc/prerm"
  @ONLY
  )
