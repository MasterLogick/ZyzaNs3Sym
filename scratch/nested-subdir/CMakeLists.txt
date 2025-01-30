
find_package(OpenSSL REQUIRED Crypto)

include(FetchContent)

FetchContent_Declare(
        CapnProto
        GIT_REPOSITORY https://github.com/capnproto/capnproto.git
        GIT_TAG 1a0e12c0a3ba1f0dbbad45ddfef555166e0a14fc # tag: v1.0.2
        GIT_SHALLOW TRUE
)
set(SECP256K1_BUILD_BENCHMARK OFF)
set(SECP256K1_BUILD_TESTS OFF)
set(SECP256K1_BUILD_EXHAUSTIVE_TESTS OFF)
set(SECP256K1_BUILD_CTIME_TESTS OFF)
set(SECP256K1_BUILD_EXAMPLES OFF)
FetchContent_Declare(
        libsecp256l1
        GIT_REPOSITORY https://github.com/bitcoin-core/secp256k1.git
        GIT_TAG e3a885d42a7800c1ccebad94ad1e2b82c4df5c65
        GIT_SHALLOW TRUE
)

set(USE_LIBCPP OFF)
set(BUILD_UVW_LIBS ON)
set(BUILD_UVW_SHARED_LIB OFF)
set(LIBUV_BUILD_SHARED OFF)
set(BUILD_TESTING OFF)
FetchContent_Declare(
        uvw
        GIT_REPOSITORY https://github.com/skypjack/uvw.git
        GIT_TAG d32ddd297034119c57a255325f43706a11d489a6
        GIT_SHALLOW TRUE
)

FetchContent_MakeAvailable(CapnProto libsecp256l1 uvw)


capnp_generate_cpp(zyzaCapnpSources zyzaCapnpHeaders lib/zyza.capnp)

add_library(zyza STATIC
        ${zyzaCapnpSources}
        lib/ZyzaReplica.cpp
        lib/ZyzaReplica.h
        lib/ZyzaClientRequest.cpp
        lib/ZyzaClientRequest.h
        lib/Endpoint.cpp
        lib/Endpoint.h
        lib/MessageHeader.h
        lib/ZyzaCommon.cpp
        lib/ZyzaCommon.h
        lib/FallbackRequestState.h
)
target_link_libraries(zyza PUBLIC CapnProto::capnp-rpc secp256k1 uvw::uvw-static uv::uv-static OpenSSL::Crypto)
target_include_directories(zyza PUBLIC ${CMAKE_CURRENT_BINARY_DIR})

# Link the custom library to the scratch executable
build_exec(
        EXECNAME scratch-zyza-sim
        SOURCE_FILES main.cc ZyzaInfiniteClient.cpp
        LIBRARIES_TO_LINK zyza
        ${libcore} ${libinternet} ${libapplications} ${libcsma} ${libpoint-to-point} ${libpoint-to-point-layout}
        EXECUTABLE_DIRECTORY_PATH ${CMAKE_OUTPUT_DIRECTORY}/scratch/nested-subdir
)
