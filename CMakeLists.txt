cmake_minimum_required(VERSION 3.22)
project(HttpFilterEngine)

set(CMAKE_CXX_STANDARD 20)

set(BUILD_SHARED_LIBS OFF)

set(Boost_USE_STATIC_LIBS ON)
set(Boost_USE_MULTITHREADED ON)
set(Boost_USE_STATIC_RUNTIME ON)
set(BOOST_ALL_DYN_LINK OFF)

set(EXAMPLE_INCLUDE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/include)
add_executable(example
    example/example.cpp
)

set(LOGGER_INCLUDE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/deps/logger/include)
add_library(logger STATIC
    deps/logger/src/logger.cpp  
)

set(WINDIVERT_LIB_INCLUDE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/deps/windivert-lib/include)
add_library(windivert_lib STATIC
    deps/windivert-lib/src/windivert.c  
)

set(GUMBO_PARSER_INCLUDE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/deps/gumbo-parser/include)
add_library(gumbo_parser STATIC
    deps/gumbo-parser/src/parser.c
    deps/gumbo-parser/src/string_buffer.c
    deps/gumbo-parser/src/string_piece.c   
    deps/gumbo-parser/src/tag.c   
    deps/gumbo-parser/src/tokenizer.c   
    deps/gumbo-parser/src/utf8.c   
    deps/gumbo-parser/src/util.c   
    deps/gumbo-parser/src/vector.c   
)

set(HTTP_FILTER_ENGINE_INCLUDE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/include)
add_library(http_filter_engine STATIC
    src/httpengine/HttpFilteringEngineControl.cpp

    src/http/client/x509_cert_utilities.cpp
    
    src/httpengine/mitm/diversion/BaseDiverter.cpp
    src/httpengine/mitm/diversion/DiversionControl.cpp
    src/httpengine/mitm/diversion/impl/win/WinDiverter.cpp
    src/httpengine/mitm/http/BaseHttpTransaction.cpp
    src/httpengine/mitm/http/HttpRequest.cpp
    src/httpengine/mitm/http/HttpResponse.cpp
    src/httpengine/mitm/secure/BaseInMemoryCertificateStore.cpp
    src/httpengine/mitm/secure/TlsCapableHttpBridge.cpp
    src/httpengine/mitm/secure/WindowsInMemoryCertificateStore.cpp
)

set(HTTP_PARSER_INCLUDE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/deps/http-parser/include)
add_library(http_parser STATIC
    deps/http-parser/src/http_parser.c   
)

set(GQ_INCLUDE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/deps/gq/include)
add_library(gq STATIC
    deps/gq/src/AttributeSelector.cpp
    deps/gq/src/BinarySelector.cpp
    deps/gq/src/Document.cpp
    deps/gq/src/Node.cpp
    deps/gq/src/NodeMutationCollection.cpp
    deps/gq/src/Parser.cpp
    deps/gq/src/Selection.cpp
    deps/gq/src/Selector.cpp
    deps/gq/src/Serializer.cpp
    deps/gq/src/SpecialTraits.cpp
    deps/gq/src/TextSelector.cpp
    deps/gq/src/TreeMap.cpp
    deps/gq/src/UnarySelector.cpp
    deps/gq/src/Util.cpp
)

FIND_PACKAGE(Threads REQUIRED)
SET(Boost_USE_MULTITHREADED ON)

find_package(Boost REQUIRED)
set(Boost_USE_STATIC_LIBS ON)

find_package(OpenSSL REQUIRED)
set(OPENSSL_USE_STATIC_LIBS ON)

find_package(ZLIB REQUIRED)
set(ZLIB_USE_STATIC_LIBS ON)

find_package(BZip2 REQUIRED)
set(BZIP2_USE_STATIC_LIBS ON)

find_package(SqliteOrm REQUIRED)
set(SQLITEORM_USE_STATIC_LIBS ON)

target_link_libraries(example PUBLIC http_filter_engine logger sqlite_orm::sqlite_orm)
target_include_directories(example PUBLIC ${TEST_INCLUDE_DIR})
target_compile_options(example PUBLIC /bigobj)  

target_link_libraries(logger PUBLIC boost::boost)
target_include_directories(logger PUBLIC ${LOGGER_INCLUDE_DIR})

target_include_directories(windivert_lib PUBLIC ${WINDIVERT_LIB_INCLUDE_DIR})

target_include_directories(gumbo_parser PUBLIC ${GUMBO_PARSER_INCLUDE_DIR})                                                             

target_link_libraries(gq PUBLIC gumbo_parser boost::boost)
target_include_directories(gq PUBLIC ${GQ_INCLUDE_DIR})                                                                                 

target_include_directories(http_parser PUBLIC ${HTTP_PARSER_INCLUDE_DIR})                                                               

target_link_libraries(http_filter_engine PUBLIC gq boost::boost http_parser windivert_lib openssl::openssl BZip2::BZip2 ZLIB::ZLIB)
target_include_directories(http_filter_engine PUBLIC ${HTTP_FILTER_ENGINE_INCLUDE_DIR} ${WINDIVERT_LIB_INCLUDE_DIR})
target_compile_options(http_filter_engine PUBLIC /bigobj)                                                                               

if(WIN32)
    target_compile_definitions(example PUBLIC BOOST_NETWORK_ENABLE_HTTPS BOOST_ASIO_SEPARATE_COMPILATION WIN32_LEAN_AND_MEAN)
    target_compile_definitions(http_filter_engine PUBLIC BOOST_NETWORK_ENABLE_HTTPS BOOST_ASIO_SEPARATE_COMPILATION WIN32_LEAN_AND_MEAN BOOST_OS_WINDOWS HTTP_FILTERING_ENGINE_USE_EX)
    target_link_libraries(http_filter_engine PUBLIC crypt32 iphlpapi)                                                           
endif()
