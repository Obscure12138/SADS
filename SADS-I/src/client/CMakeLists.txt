#src/client

add_library(chunker STATIC chunker.cpp)
add_library(fingerprinter STATIC fingerprinter.cpp)
add_library(keyClient STATIC keyClient.cpp)
#add_library(encoder STATIC encoder.cpp)
add_library(sender STATIC sender.cpp)
add_library(powClient STATIC powClient.cpp)
add_library(characterer STATIC characterer.cpp)
#add_library(recvDecode STATIC recvDecode.cpp)
#add_library(retriever STATIC retriever.cpp)
add_executable(client-SaDedup clientMain.cpp)

target_link_libraries(client-SaDedup ${CLIENT_OBJ} ${LINK_OBJ})