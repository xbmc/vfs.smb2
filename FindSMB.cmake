#.rst:
# FindSMB
# -------
# Finds the libsmb library
#
# This will will define the following variables::
#
# SMB_FOUND - system has libsmb
# SMB_INCLUDE_DIRS - the libsmb include directory
# SMB_LIBRARIES - the libsmb libraries
# SMB_DEFINITIONS - the libsmb compile definitions

if(PKG_CONFIG_FOUND)
  pkg_check_modules(PC_SMB libsmb2 QUIET)
endif()

find_path(SMB_INCLUDE_DIR smb2/libsmb2.h
                          PATHS ${PC_SMB_INCLUDEDIR})

set(SMB_VERSION ${PC_SMB_VERSION})

include(FindPackageHandleStandardArgs)

find_library(SMB_LIBRARY NAMES smb2
                         PATHS ${PC_SMB_LIBDIR})

find_package_handle_standard_args(SMB
                                  REQUIRED_VARS SMB_LIBRARY SMB_INCLUDE_DIR
                                  VERSION_VAR SMB_VERSION)

if(SMB_FOUND)
  set(SMB_LIBRARIES ${SMB_LIBRARY})
  set(SMB_INCLUDE_DIRS ${SMB_INCLUDE_DIR})
  set(SMB_DEFINITIONS -DHAVE_LIBSMB=1)
endif()

mark_as_advanced(SMB_INCLUDE_DIR SMB_LIBRARY)
