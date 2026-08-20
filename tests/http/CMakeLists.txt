# HTTP client tests, driven entirely through an in-process mock transport.
#
# No network, no live server, and no dependence on the build's HTTP backend --
# these run identically in a TAMGA_HTTP=none build, which is the point: what
# is under test is request construction, the retry policy and response
# handling, none of which involve sockets.

tamga_add_test(test_http_client    client_test.c)
tamga_add_test(test_http_endpoints endpoints_test.c)
