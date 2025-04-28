#src/keymanage
add_library(keyServer STATIC keyServer.cpp)

add_executable(ks-SaDedup keyServerMain.cpp)
#target_link_libraries(keymanager keyServer)
target_link_libraries(ks-SaDedup ${KEYSERVER_OBJ} ${LINK_OBJ})