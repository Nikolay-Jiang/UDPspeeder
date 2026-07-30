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

    // Harness self-check. Every later task's assertions are only as trustworthy
    // as TCHECK's ability to actually FAIL, so exercise the failure path once
    // against scratch counters, then restore them.
    {
        int saved_checks = g_checks;
        int saved_failures = g_failures;
        g_checks = 0;
        g_failures = 0;
        printf("---- selftest: one deliberate FAIL line follows, it is expected ----\n");
        TCHECK(1 == 0, "deliberate failure proving the harness counts failures");
        bool harness_ok = (g_checks == 1 && g_failures == 1);
        g_checks = saved_checks;
        g_failures = saved_failures;
        printf("---- selftest: end of deliberate failure ----\n");
        TCHECK(harness_ok, "TCHECK must count a failing check exactly once");
    }

    printf("test_mode selftest: %d checks, %d failures\n", g_checks, g_failures);
    return g_failures == 0 ? 0 : 1;
}
