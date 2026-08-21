/*
 * validate_license.c -- the shortest useful thing this SDK does.
 *
 * Authenticates with the end user's own licence key and asks the server
 * whether it is valid. This is the call an application makes at startup.
 *
 *   validate_license <account-id> <license-key> [host]
 *
 * Exit status: 0 valid, 1 not valid, 2 the check could not be made -- which
 * is a distinction worth preserving in real software too. "The network is
 * down" is not "your licence is invalid", and treating it as such is how a
 * licensing system locks out a paying customer on an aeroplane.
 */
#include <stdio.h>
#include <string.h>

#include "tamga.h"

int main(int argc, char **argv) {
    const char *account_id;
    const char *license_key;
    const char *host = "api.tamga.sh";
    TamgaClient *client = NULL;
    TamgaResponse *response = NULL;
    TamgaErrorCode code;
    int exit_status = 2;

    if (argc < 3) {
        (void)fprintf(stderr, "usage: %s <account-id> <license-key> [host]\n", argv[0]);
        return 2;
    }
    account_id = argv[1];
    license_key = argv[2];
    if (argc > 3) {
        host = argv[3];
    }

    if (!tamga_has_builtin_transport()) {
        (void)fprintf(stderr, "this build has no HTTP transport (TAMGA_HTTP=none); register one "
                              "with tamga_client_set_transport()\n");
        return 2;
    }

    code = tamga_client_new(account_id, host, &client);
    if (code != TAMGA_OK) {
        (void)fprintf(stderr, "could not create the client: %s\n", tamga_last_error_message());
        return 2;
    }

    /* The licence transport authenticates with the end user's own key, which
     * is what an embedded application has. The licence's policy has to opt
     * in: authentication_strategy must be LICENSE or MIXED. It defaults to
     * TOKEN, and NONE refuses licence keys too -- either one answers 401
     * LICENSE_NOT_ALLOWED on every call, which is a provisioning
     * precondition rather than a bad key, so retrying never helps. */
    code = tamga_client_set_auth(client, TAMGA_AUTH_LICENSE, license_key, NULL);
    if (code != TAMGA_OK) {
        (void)fprintf(stderr, "could not set credentials: %s\n", tamga_last_error_message());
        tamga_client_free(client);
        return 2;
    }

    code = tamga_client_validate_by_key(client, license_key, NULL, &response);
    if (code != TAMGA_OK) {
        const char *server_code = tamga_response_error_code(response);
        (void)fprintf(stderr, "validation could not be performed: %s (%s)%s%s\n",
                      tamga_error_name(code),
                      tamga_last_error_message() ? tamga_last_error_message() : "",
                      server_code ? " server code: " : "", server_code ? server_code : "");
    } else {
        const char *outcome = tamga_response_validation_code(response);
        const char *detail = tamga_response_validation_detail(response);

        printf("valid:  %s\n", tamga_response_validation_is_valid(response) ? "yes" : "no");
        printf("code:   %s\n", outcome ? outcome : "(none)");
        printf("detail: %s\n", detail ? detail : "(none)");
        exit_status = tamga_response_validation_is_valid(response) ? 0 : 1;
    }

    tamga_response_free(response);
    tamga_client_free(client);
    return exit_status;
}
