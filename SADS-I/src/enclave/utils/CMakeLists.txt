#src/enclave/utils
add_library(common common.cpp)
add_library(logfile logfile.c)
add_library(agent_wget agent_wget.cpp)
add_library(base64 base64.c)
add_library(byteorder byteorder.c)
add_library(sgx_crypto crypto.c)
add_library(hexutil hexutil.c)
add_library(POW_json json.cpp)
add_library(sgxErrorSupport sgxErrorSupport.cpp)
add_library(iasrequest iasrequest.cpp)
 