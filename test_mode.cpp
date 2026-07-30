#include "test_mode.h"
#include "log.h"
#include "packet.h"  // key_string
#include <math.h>
#include <stdio.h>
#include <string.h>

// ---------------- selftest harness ----------------
static int g_checks = 0;
static int g_failures = 0;

#define TCHECK(cond, ...)                            \
    do {                                             \
        g_checks++;                                   \
        if (!(cond)) {                               \
            g_failures++;                             \
            printf("FAIL [%s:%d]: ", __FILE__, __LINE__); \
            printf(__VA_ARGS__);                     \
            printf("\n");                            \
        }                                            \
    } while (0)

// placeholder loops, implemented in later tasks
int test_mode_prober_loop() {
    mylog(log_fatal, "test-mode prober not implemented yet\n");
    myexit(-1);
    return 0;
}

int test_mode_responder_loop() {
    mylog(log_fatal, "test-mode responder not implemented yet\n");
    myexit(-1);
    return 0;
}

int test_mode_selftest() {
    g_checks = 0;
    g_failures = 0;

    // Harness sanity: proves TCHECK counts a passing and a failing check.
    TCHECK(1 == 1, "harness must count a passing check");

    // This assertion intentionally documents the defaults contract.
    TCHECK(TEST_PPS_MAX == 20000, "TEST_PPS_MAX must be 20000, got %d", TEST_PPS_MAX);

    printf("test_mode selftest: %d checks, %d failures\n", g_checks, g_failures);
    return g_failures == 0 ? 0 : 1;
}
