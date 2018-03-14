project(vfs.smb2)

cmake_minimum_required(VERSION 2.6)

list(APPEND CMAKE_MODULE_PATH ${PROJECT_SOURCE_DIR})

enable_language(CXX)

find_package(SMB REQUIRED)
find_package(Kodi REQUIRED)
find_package(p8-platform REQUIRED)
find_package(kodiplatform REQUIRED)

include_directories(${KODI_INCLUDE_DIR}/.. # Hack way with "/..", need bigger Kodi cmake rework to match right include ways
                    ${kodiplatform_INCLUDE_DIRS}
                    ${p8-platform_INCLUDE_DIRS}
                    ${SMB_INCLUDE_DIRS})

set(SMB_HEADERS src/SMBConnection.h
                src/SMBFile.h)

set(SMB_SOURCES src/SMBConnection.cpp
                src/SMBFile.cpp)

set(DEPLIBS ${SMB_LIBRARIES} ${p8-platform_LIBRARIES} ${kodiplatform_LIBRARIES})

add_definitions(-D_LARGEFILE64_SOURCE
                -D_FILE_OFFSET_BITS=64
                -D__STDC_FORMAT_MACROS)

build_addon(vfs.smb2 SMB DEPLIBS)
