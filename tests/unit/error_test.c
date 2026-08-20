#include "tamga_test.h"

#include "tamga.h"
#include "tamga_error.h"

TT_TEST(no_error_recorded_yields_null)
{
    tamga_error_clear();
    TT_ASSERT_NULL(tamga_last_error_message());
}

TT_TEST(setting_an_error_records_the_message)
{
    TamgaErrorCode code = tamga_error_set(TAMGA_ERR_INVALID_PEM, "missing %s marker", "BEGIN");
    TT_ASSERT_EQ_INT(code, TAMGA_ERR_INVALID_PEM);
    TT_ASSERT_EQ_STR(tamga_last_error_message(), "missing BEGIN marker");
}

/* The contract every consumer relies on: TAMGA_OK implies NULL, always. */
TT_TEST(setting_ok_clears_rather_than_records)
{
    (void)tamga_error_set(TAMGA_ERR_UNKNOWN, "boom");
    TT_ASSERT_NOT_NULL(tamga_last_error_message());
    TT_ASSERT_EQ_INT(tamga_error_set(TAMGA_OK, "ignored"), TAMGA_OK);
    TT_ASSERT_NULL(tamga_last_error_message());
}

TT_TEST(a_null_format_falls_back_to_the_code_name)
{
    (void)tamga_error_set(TAMGA_ERR_EXPIRED, NULL);
    TT_ASSERT_EQ_STR(tamga_last_error_message(), "TAMGA_ERR_EXPIRED");
}

TT_TEST(an_overlong_message_is_truncated_and_marked)
{
    char big[TAMGA_ERROR_MESSAGE_CAP * 2];
    const char *msg;
    size_t len;
    memset(big, 'x', sizeof(big) - 1u);
    big[sizeof(big) - 1u] = '\0';

    (void)tamga_error_set(TAMGA_ERR_UNKNOWN, "%s", big);
    msg = tamga_last_error_message();
    TT_ASSERT_NOT_NULL(msg);
    len = strlen(msg);
    TT_ASSERT_EQ_SIZE(len, (size_t)(TAMGA_ERROR_MESSAGE_CAP - 1));
    TT_ASSERT_EQ_STR(&msg[len - 3u], "...");
}

TT_TEST(error_names_cover_every_declared_code)
{
    TT_ASSERT_EQ_STR(tamga_error_name(TAMGA_OK), "TAMGA_OK");
    TT_ASSERT_EQ_STR(tamga_error_name(TAMGA_ERR_INVALID_PEM), "TAMGA_ERR_INVALID_PEM");
    TT_ASSERT_EQ_STR(tamga_error_name(TAMGA_ERR_LENGTH_INVALID), "TAMGA_ERR_LENGTH_INVALID");
    TT_ASSERT_EQ_STR(tamga_error_name(TAMGA_ERR_EXPIRED), "TAMGA_ERR_EXPIRED");
    TT_ASSERT_EQ_STR(tamga_error_name(TAMGA_ERR_OUT_OF_MEMORY), "TAMGA_ERR_OUT_OF_MEMORY");
    TT_ASSERT_EQ_STR(tamga_error_name((TamgaErrorCode)9999), "TAMGA_ERR_UNKNOWN");
}

int main(void)
{
    TT_RUN(no_error_recorded_yields_null);
    TT_RUN(setting_an_error_records_the_message);
    TT_RUN(setting_ok_clears_rather_than_records);
    TT_RUN(a_null_format_falls_back_to_the_code_name);
    TT_RUN(an_overlong_message_is_truncated_and_marked);
    TT_RUN(error_names_cover_every_declared_code);
    return TT_SUMMARY();
}
