# Try to find Zlog


find_path (Zlog_INCLUDE_DIR
    NAMES zlog.h
    PATHS /usr/local/include/ /usr/include/ ${CMAKE_SOURCE_DIR}/thirdparty/include/ )
find_library(Zlog_LIBRARY
    NAMES zlog
    PATHS /usr/local/lib/ /usr/lib/ ${CMAKE_SOURCE_DIR}/thirdparty/lib/)

if (Zlog_INCLUDE_DIR AND Zlog_LIBRARY) 
    set (zlog_FOUND TRUE)
    message(STATUS "Found Zlog include file: ${Zlog_INCLUDE_DIR}")
    message(STATUS "Found Zlog library: ${Zlog_LIBRARY}")
endif(Zlog_INCLUDE_DIR AND Zlog_LIBRARY)