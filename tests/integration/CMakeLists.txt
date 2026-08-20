# Integration tests: the offline file formats end to end, against fixtures
# produced by an independent implementation.

tamga_add_test(test_license_file license_file_test.c)
tamga_add_test(test_machine_file machine_file_test.c)
tamga_add_test(test_proof        proof_test.c)
