cmake_minimum_required(VERSION 3.16)
project(cert_helper CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE RelWithDebInfo)
endif()

add_compile_options(-Wall -Wextra)

find_package(OpenSSL REQUIRED)
find_package(Threads REQUIRED)

# Разбор аргументов командной строки у демона и у cert-helper-cli — через
# boost::program_options (вместо самодельного цикла по argv). Нужен
# только этим двум исполняемым файлам — тестам и dbus_server.cpp не
# требуется, поэтому подключается точечно, а не в cert_helper_target_common.
find_package(Boost REQUIRED COMPONENTS program_options)

# Транспорт демона — D-Bus (sd-bus из libsystemd). См. README.md за
# обоснованием выбора sd-bus вместо libdbus-1/GDBus.
find_package(PkgConfig REQUIRED)
pkg_check_modules(SDBUS REQUIRED libsystemd)

# Общие исходники транспортного слоя, используемые и демоном, и тестами.
set(CERT_HELPER_DBUS_SERVER_SOURCES
    src/ipc/dbus_server.cpp
)

function(cert_helper_target_common name)
    target_include_directories(${name} PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/include
        ${CMAKE_CURRENT_SOURCE_DIR}/src
        ${SDBUS_INCLUDE_DIRS}
    )
    target_link_libraries(${name} PRIVATE
        OpenSSL::SSL OpenSSL::Crypto Threads::Threads ${SDBUS_LIBRARIES}
    )
    target_link_directories(${name} PRIVATE ${SDBUS_LIBRARY_DIRS})
    target_compile_options(${name} PRIVATE ${SDBUS_CFLAGS_OTHER})
endfunction()

# ---------------------------------------------------------------------------
# cert-helper (демон)
# ---------------------------------------------------------------------------
add_executable(cert-helper
    src/daemon_main.cpp
    ${CERT_HELPER_DBUS_SERVER_SOURCES}
)
cert_helper_target_common(cert-helper)
target_link_libraries(cert-helper PRIVATE Boost::program_options)

# ---------------------------------------------------------------------------
# cert-helper-cli (утилита командной строки, examples/standalone_fetch_cli.cpp)
# ---------------------------------------------------------------------------
add_executable(cert-helper-cli
    examples/standalone_fetch_cli.cpp
)
cert_helper_target_common(cert-helper-cli)
target_link_libraries(cert-helper-cli PRIVATE Boost::program_options)

# ---------------------------------------------------------------------------
# cert-helper-cache-tool (ROADMAP.md, раздел 2, пункт 16): экспорт/импорт
# кэша между хостами — самостоятельная файловая утилита, НЕ линкуется с
# sd-bus/OpenSSL (не нужны — см. cache_tool_cli.cpp).
# ---------------------------------------------------------------------------
add_executable(cert-helper-cache-tool
    examples/cache_tool_cli.cpp
)
target_include_directories(cert-helper-cache-tool PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${CMAKE_CURRENT_SOURCE_DIR}/src
)
target_link_libraries(cert-helper-cache-tool PRIVATE Boost::program_options)

# ---------------------------------------------------------------------------
# Тесты
# ---------------------------------------------------------------------------
option(CERT_HELPER_BUILD_TESTS "Build cert-helper unit/integration tests" ON)

if(CERT_HELPER_BUILD_TESTS)
    enable_testing()

    function(add_cert_helper_test name)
        add_executable(${name} ${ARGN})
        cert_helper_target_common(${name})
        add_test(NAME ${name} COMMAND ${name})
    endfunction()

    add_cert_helper_test(test_cache tests/test_cache.cpp)
    add_cert_helper_test(test_logging tests/test_logging.cpp)
    add_cert_helper_test(test_audit_log tests/test_audit_log.cpp)
    add_cert_helper_test(test_aia_extraction tests/test_aia_extraction.cpp)
    add_cert_helper_test(test_crl_delta_extraction tests/test_crl_delta_extraction.cpp)
    add_cert_helper_test(test_dns_cache tests/test_dns_cache.cpp)
    add_cert_helper_test(test_cache_warmup tests/test_cache_warmup.cpp)
    add_cert_helper_test(test_cache_export tests/test_cache_export.cpp)
    add_cert_helper_test(test_net_policy tests/test_net_policy.cpp)
    add_cert_helper_test(test_two_tier_cache tests/test_two_tier_cache.cpp)
    add_cert_helper_test(test_http_cache_hints tests/test_http_cache_hints.cpp)
    add_cert_helper_test(test_http_keepalive tests/test_http_keepalive.cpp)
    add_cert_helper_test(test_https_support tests/test_https_support.cpp)
    add_cert_helper_test(test_ldap_support tests/test_ldap_support.cpp)
    add_cert_helper_test(test_client_server_roundtrip
        tests/test_client_server_roundtrip.cpp
        ${CERT_HELPER_DBUS_SERVER_SOURCES}
    )
endif()
