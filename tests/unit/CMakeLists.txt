# Unit tests: one executable per internal module, named test_unit_<module>.

tamga_add_test(test_unit_buf     buf_test.c)
tamga_add_test(test_unit_base64  base64_test.c)
tamga_add_test(test_unit_hex     hex_test.c)
tamga_add_test(test_unit_uuid    uuid_test.c)
tamga_add_test(test_unit_rfc3339 rfc3339_test.c)
tamga_add_test(test_unit_mem     mem_test.c)
tamga_add_test(test_unit_error   error_test.c)
tamga_add_test(test_unit_json    json_test.c)
tamga_add_test(test_unit_hash    hash_test.c)
tamga_add_test(test_unit_gcm     gcm_test.c)
tamga_add_test(test_unit_fe25519 fe25519_test.c)
tamga_add_test(test_unit_ed25519 ed25519_test.c)
tamga_add_test(test_unit_bn      bn_test.c)
tamga_add_test(test_unit_rsa     rsa_test.c)
tamga_add_test(test_unit_ecdsa   ecdsa_test.c)
tamga_add_test(test_unit_signing_key signing_key_test.c)

# Whitebox: p256.c's Montgomery arithmetic is static, and should stay that way.
tamga_add_whitebox_test(test_unit_p256 p256_test.c
    DEPS ${CMAKE_SOURCE_DIR}/src/tamga_mem.c)

# Whitebox: the library built against an allocator that can be made to fail,
# so the OUT_OF_MEMORY branches are reachable at all. tamga_mem.c is excluded
# from the list because tests/support/failing_alloc.c includes it.
set(TAMGA_ALLOC_FAILURE_SOURCES ${TAMGA_SOURCES})
list(FILTER TAMGA_ALLOC_FAILURE_SOURCES EXCLUDE REGEX "src/tamga_mem\\.c$")
tamga_add_whitebox_test(test_unit_alloc_failure alloc_failure_test.c
    DEPS ${TAMGA_ALLOC_FAILURE_SOURCES} ${CMAKE_SOURCE_DIR}/tests/support/failing_alloc.c)
tamga_configure_http(test_unit_alloc_failure)
tamga_add_test(test_unit_api     api_test.c)
