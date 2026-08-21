# Integration tests: the offline file formats end to end, against fixtures
# produced by an independent implementation.

tamga_add_test(test_license_file license_file_test.c)
tamga_add_test(test_machine_file machine_file_test.c)
# The only machine-file suite driven by files the SERVER produced. Every other
# machine-file fixture in this tree was generated here, and reproduced this
# SDK's own misreading of the format.
tamga_add_test(test_server_machine_files server_machine_files_test.c)
tamga_add_test(test_proof        proof_test.c)
tamga_add_test(test_cross_sdk    cross_sdk_test.c)
