/*
 * activate_machine.c -- the full activation flow, including the part most
 * integrations get wrong.
 *
 *   activate_machine <account-id> <license-id> <license-key> <fingerprint> [host]
 *
 * An over-limit activation is reported one of two ways, and which one depends
 * on the licence policy's overage strategy rather than on anything the client
 * does. Under a strict strategy the CREATE is rejected outright with 422 and
 * a TAMGA_ERR_*_LIMIT_EXCEEDED code. Under ALLOW_ACCESS or
 * ALLOW_1_25X_OVERAGE the create succeeds anyway and the limit shows up only
 * on the next validation. An application that stops after the create believes
 * it activated successfully in the second case, and hands the user a working
 * copy it was not entitled to.
 *
 * tamga_client_activate_machine() covers both: it returns the limit code
 * directly when the creation is refused, and otherwise composes
 * create-then-validate and -- when asked -- deletes the machine it just
 * created if the validation comes back over-limit, so a rejected activation
 * does not leave an orphaned row counting against the customer's seats.
 *
 * tamga_validation_code_from_error() folds the creation-time vocabulary onto
 * the validation one, which is what lets the two paths share a branch below.
 */
#include <stdio.h>

#include "tamga.h"

int main(int argc, char **argv) {
    const char *host = "api.tamga.sh";
    TamgaClient *client = NULL;
    TamgaResponse *response = NULL;
    TamgaErrorCode code;
    int exit_status = 2;

    if (argc < 5) {
        (void)fprintf(stderr,
                      "usage: %s <account-id> <license-id> <license-key> <fingerprint> "
                      "[host]\n",
                      argv[0]);
        return 2;
    }
    if (argc > 5) {
        host = argv[5];
    }

    code = tamga_client_new(argv[1], host, &client);
    if (code == TAMGA_OK) {
        code = tamga_client_set_auth(client, TAMGA_AUTH_LICENSE, argv[3], NULL);
    }
    if (code != TAMGA_OK) {
        (void)fprintf(stderr, "setup failed: %s\n", tamga_last_error_message());
        tamga_client_free(client);
        return 2;
    }

    /* A fingerprint should identify the machine stably across reboots and
     * upgrades -- a hardware id, a stored UUID -- and be the same value the
     * machine file is later decrypted with. */
    code = tamga_client_activate_machine(client, argv[2], argv[4], "{\"platform\":\"linux\"}", NULL,
                                         true, &response);
    if (code != TAMGA_OK) {
        const char *server_code = tamga_response_error_code(response);
        TamgaValidationCode limit = tamga_validation_code_from_error(code);

        if (code == TAMGA_ERR_FINGERPRINT_TAKEN) {
            /* Already activated on this machine. Usually not an error: it is
             * what a second launch looks like. */
            printf("this machine is already registered\n");
            exit_status = 0;
        } else if (limit != TAMGA_VALIDATION_UNKNOWN) {
            /* A strict overage strategy: the creation itself was refused, so
             * no machine row exists and none had to be removed. The same
             * condition under ALLOW_ACCESS would have arrived below as a
             * validation code instead. */
            printf("the licence is at its limit (%s); no machine was created\n",
                   tamga_validation_code_name(limit));
            exit_status = 1;
        } else if (code == TAMGA_ERR_LICENSE_NOT_ALLOWED) {
            /* Not a bad key, and not worth retrying: the policy's
             * authentication_strategy has to be LICENSE or MIXED, and it
             * defaults to TOKEN. */
            (void)fprintf(stderr, "this licence's policy does not permit licence-key "
                                  "authentication\n");
        } else {
            (void)fprintf(stderr, "activation failed: %s%s%s\n", tamga_error_name(code),
                          server_code ? " / " : "", server_code ? server_code : "");
        }
    } else {
        const char *outcome = tamga_response_validation_code(response);
        printf("valid: %s\ncode:  %s\n",
               tamga_response_validation_is_valid(response) ? "yes" : "no",
               outcome ? outcome : "(none)");
        if (!tamga_response_validation_is_valid(response) &&
            tamga_validation_code_is_overage(tamga_response_validation_code_enum(response))) {
            printf("the licence is at its limit; the machine just created has been "
                   "removed again\n");
        }
        exit_status = tamga_response_validation_is_valid(response) ? 0 : 1;
    }

    tamga_response_free(response);
    tamga_client_free(client);
    return exit_status;
}
