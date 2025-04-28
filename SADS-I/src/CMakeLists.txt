#/
set(CMAKE_MODULE_PATH /usr/share/cmake-3.10/Modules/)

find_package(Boost 1.36.0 REQUIRED COMPONENTS thread system serialization)
if(Boost_FOUND)
  include_directories(${Boost_INCLUDE_DIRS})
  link_directories(${BOOST_LIBRARY_DIR})
endif()

set(OPENSSL_INCLUDE_PATH /usr/include/)
set(OPENSSL_LIBRARY_PATH /usr/lib/x86_64-linux-gnu)

set(PBC_LIBRARY_PATH /usr/local/lib/libpbc.a)

include_directories( ../include)
link_directories(util)

set(BOOST_LIBRARY_OBJ boost_thread boost_system boost_serialization)
set(SYSTEM_LIBRARY_OBJ pthread rt dl)
set(OPENSSL_LIBRARY_OBJ ssl crypto)
set(LEVELDB_LIBRARY_OBJ pthread leveldb)
set(UTIL_OBJ configure cryptoPrimitive SSL_TLS database)

set(LINK_OBJ ${UTIL_OBJ} ${OPENSSL_LIBRARY_OBJ} ${LEVELDB_LIBRARY_OBJ} ${BOOST_LIBRARY_OBJ} ${UTIL_OBJ} ${SYSTEM_LIBRARY_OBJ})

set(CLIENT_OBJ chunker fingerprinter keyClient  powClient sender characterer)
set(SERVER_OBJ dataSR  dedupCore  storage ) 
set(KEYSERVER_OBJ keyServer )

#-fno-builtin-memset

set (CMAKE_SYSTEM_NAME Linux )
if (NOT CMAKE_BUILD_TYPE)
   set (CMAKE_BUILD_TYPE "Release")
   message (
      STATUS "No CMAKE_BUILD_TYPE selected, defaulting to ${CMAKE_BUILD_TYPE}"
   )
endif ()

set(CMAKE_C_FLAGS_DEBUG "-Wall -std=c1x -g -ggdb -g2") 
set(CMAKE_CXX_FLAGS_DEBUG "-Wall -std=c++11 -g -ggdb -g2 -fno-omit-frame-pointer -fsanitize=leak")
set(CMAKE_C_FLAGS_RELEASE "-O3 -std=c1x") 
set(CMAKE_CXX_FLAGS_RELEASE "-O3 -std=c++11")
set(CMAKE_MODULE_PATH /usr/share/cmake-3.10/Modules/)

# SET (CMAKE_C_COMPILER             "/usr/bin/clang")
# SET (CMAKE_CXX_COMPILER             "/usr/bin/clang++")
# SET (CMAKE_AR      "/usr/bin/llvm-ar")
# SET (CMAKE_LINKER  "/usr/bin/llvm-ld")
# SET (CMAKE_NM      "/usr/bin/llvm-nm")
# SET (CMAKE_OBJDUMP "/usr/bin/llvm-objdump")
# SET (CMAKE_RANLIB  "/usr/bin/llvm-ranlib")

add_subdirectory(util)
add_subdirectory(keymanage)
add_subdirectory(client)
add_subdirectory(server)
