# Unit tests: one executable per internal module, named test_unit_<module>.

tamga_add_test(test_unit_buf     buf_test.c)
tamga_add_test(test_unit_base64  base64_test.c)
tamga_add_test(test_unit_hex     hex_test.c)
tamga_add_test(test_unit_uuid    uuid_test.c)
tamga_add_test(test_unit_rfc3339 rfc3339_test.c)
tamga_add_test(test_unit_mem     mem_test.c)
tamga_add_test(test_unit_error   error_test.c)
