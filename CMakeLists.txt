cmake_minimum_required(VERSION 3.5)
project(vfs.smb2)

list(APPEND CMAKE_MODULE_PATH ${PROJECT_SOURCE_DIR})

find_package(SMB REQUIRED)
find_package(Kodi REQUIRED)
find_package(p8-platform REQUIRED)

include_directories(${KODI_INCLUDE_DIR}/.. # Hack way with "/..", need bigger Kodi cmake rework to match right include ways
                    ${p8-platform_INCLUDE_DIRS}
                    ${SMB_INCLUDE_DIRS})

set(SAMBA_HEADERS src/SMBSession.h
                  src/SMBFile.h
                  src/netbios/netbios_defs.h
                  src/netbios/netbios_ns.h
                  src/netbios/netbios_query.h
                  src/netbios/netbios_utils.h)

set(SAMBA_SOURCES src/SMBSession.cpp
                  src/SMBFile.cpp
                  src/netbios/netbios_ns.cpp
                  src/netbios/netbios_query.cpp
                  src/netbios/netbios_utils.cpp)

set(DEPLIBS ${SMB_LIBRARIES} ${p8-platform_LIBRARIES})

add_definitions(-D_LARGEFILE64_SOURCE
                -D_FILE_OFFSET_BITS=64
                -D__STDC_FORMAT_MACROS
                -D_CRT_NONSTDC_NO_DEPRECATE
                -D_CRT_SECURE_NO_WARNINGS
                -D_WINSOCK_DEPRECATED_NO_WARNINGS)

build_addon(vfs.smb2 SAMBA DEPLIBS)
