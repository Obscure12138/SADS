#pbcwrapper
link_libraries(libgmp.a libgmp.so libpbc.a)

add_library(G STATIC G.cc)
add_library(G1 STATIC G1.cc)
add_library(G2 STATIC G2.cc)
add_library(GT STATIC GT.cc)
add_library(Pairing STATIC Pairing.cc)
add_library(PPPairing STATIC PPPairing.cc)
add_library(Zr STATIC Zr.cc)

target_link_libraries(G  /usr/local/lib/libgmp.a /usr/local/lib/libgmp.so /usr/local/lib/libpbc.a)
target_link_libraries(G1 /usr/local/lib/libgmp.a /usr/local/lib/libgmp.so /usr/local/lib/libpbc.a)
target_link_libraries(G2 /usr/local/lib/libgmp.a /usr/local/lib/libgmp.so /usr/local/lib/libpbc.a)
target_link_libraries(GT /usr/local/lib/libgmp.a /usr/local/lib/libgmp.so /usr/local/lib/libpbc.a)
target_link_libraries(Pairing /usr/local/lib/libgmp.a /usr/local/lib/libgmp.so /usr/local/lib/libpbc.a)
target_link_libraries(PPPairing /usr/local/lib/libgmp.a /usr/local/lib/libgmp.so /usr/local/lib/libpbc.a)
target_link_libraries(Zr /usr/local/lib/libgmp.a /usr/local/lib/libgmp.so /usr/local/lib/libpbc.a)