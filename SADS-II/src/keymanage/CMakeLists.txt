#src/keymanage

set(SGX_OPENSSL_LIBRARY_PATH /opt/intel/sgxssl/lib64)
set(SGX_LIB_PATH /opt/intel/sgxsdk/lib64)
set(SGX_OPENSSL_OBJ sgx_usgxssl)
link_directories(${SGX_OPENSSL_LIBRARY_PATH} ${SGX_LIB_PATH})


add_library(keyServer STATIC keyServer.cpp)

add_executable(keymanager-sgx keyServerMain.cpp)
#target_link_libraries(keymanager keyServer)
target_link_libraries(keymanager-sgx ${KEYSERVER_OBJ} ${LINK_OBJ} ${SGX_OPENSSL_OBJ})
