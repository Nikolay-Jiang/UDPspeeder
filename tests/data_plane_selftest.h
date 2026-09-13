// Included by test_mode.cpp after TCHECK; exercises production packet/FEC paths.
#include "packet.h"
#include "fec_manager.h"
#include "misc.h"
#include <sys/wait.h>
#include <getopt.h>

static void data_plane_auth_checks(char *plain, int plain_len) {
    const int saved_obscure = disable_obscure, saved_xor = disable_xor;
    uint8_t key[16];
    memcpy(key, g_psk, sizeof(key));
    // Check both the bare authenticated range and the actual obscured/XOR wire.
    for (int wrapped = 0; wrapped <= 1; wrapped++) {
        disable_obscure = disable_xor = !wrapped;
        char wire[buf_len], received[buf_len];
        memcpy(wire, plain, plain_len);
        int wire_len = plain_len;
        TCHECK(do_cook(wire, wire_len) == 0, "data-plane cook");
        TCHECK(wire_len == plain_len + 8 + (wrapped ? 33 : 0), "data-plane exact tag/maximum obscure overhead: %d", wire_len);
        memcpy(received, wire, wire_len);
        int len = wire_len;
        TCHECK(de_cook(received, len) == 0 && len == plain_len && memcmp(received, plain, plain_len) == 0,
               "data-plane same-key round trip, wrapped=%d", wrapped);
        // Obscure and XOR preserve byte positions in the authenticated prefix.
        // Flip one bit at EVERY byte: FEC seq/type/count/index, length, conv,
        // payload, and all eight trailer bytes. Do not recompute the tag.
        for (int byte = 0; byte < plain_len + 8; byte++) {
            memcpy(received, wire, wire_len);
            received[byte] ^= 1;
            len = wire_len;
            TCHECK(de_cook(received, len) != 0, "data-plane tamper accepted at byte=%d wrapped=%d", byte, wrapped);
        }
        uint8_t wrong[16];
        memcpy(wrong, key, sizeof(wrong));
        wrong[0] ^= 1;
        auth_key_set(wrong);
        memcpy(received, wire, wire_len);
        len = wire_len;
        TCHECK(de_cook(received, len) != 0, "data-plane wrong key accepted, wrapped=%d", wrapped);
        auth_key_set(key);
        if (!wrapped) {
            for (int short_len = 0; short_len < 8; short_len++) {
                len = short_len;
                TCHECK(de_cook(received, len) != 0, "data-plane short trailer accepted: %d", short_len);
            }
        }
    }
    disable_obscure = saved_obscure;
    disable_xor = saved_xor;
}

static int data_plane_batch_len(int sequence) {
    int slot = sequence % IO_BATCH_MAX;
    // Large packets immediately before AND after each full-batch boundary,
    // interspersed with distinct short lengths to detect stale iovec lengths.
    return slot == 0 || slot == IO_BATCH_MAX - 1 ? max_data_len + 14 : 14 + sequence % 31;
}

static void data_plane_batch_checks(const char *plain) {
    int receiver = socket(AF_INET, SOCK_DGRAM, 0);
    int sender = socket(AF_INET, SOCK_DGRAM, 0);
    TCHECK(receiver >= 0 && sender >= 0, "batch UDP sockets");
    if (receiver < 0 || sender < 0) {
        if (receiver >= 0) close(receiver);
        if (sender >= 0) close(sender);
        return;
    }
    address_t addr;
    addr.clear();
    addr.inner.ipv4.sin_family = AF_INET;
    addr.inner.ipv4.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    int ret = bind(receiver, (sockaddr *)&addr.inner, addr.get_len());
    TCHECK(ret == 0, "batch bind ephemeral loopback port");
    socklen_t addr_len = addr.get_len();
    ret |= getsockname(receiver, (sockaddr *)&addr.inner, &addr_len);
    int capacity = 1024 * 1024;
    ret |= setsockopt(receiver, SOL_SOCKET, SO_RCVBUF, &capacity, sizeof(capacity));
    timeval timeout = {2, 0};
    ret |= setsockopt(receiver, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    TCHECK(ret == 0, "batch socket setup");
    if (ret == 0) {
        dest_t dest;
        dest.type = type_fd_addr;
        dest.inner.fd_addr.fd = sender;
        dest.inner.fd_addr.addr = addr;
        dest.cook = 1;
        const int count = 2 * IO_BATCH_MAX + 1;
        u64_t drops = short_send_drop_count;
        my_send_batch_begin();
        for (int sequence = 0; sequence < count; sequence++) {
            char packet[buf_len];
            int len = data_plane_batch_len(sequence);
            memcpy(packet, plain, len);
            write_u32(packet, sequence);
            TCHECK(my_send(dest, packet, len) >= 0, "batch send sequence=%d", sequence);
            // No manual flush at either boundary: only my_send may flush.
        }
        my_send_flush();
        TCHECK(short_send_drop_count == drops, "batch must not drop a short send");
        for (int sequence = 0; sequence < count; sequence++) {
            char packet[buf_len], expected[buf_len];
            int expected_len = data_plane_batch_len(sequence);
            int len = recv(receiver, packet, sizeof(packet), MSG_TRUNC);
            TCHECK(len == expected_len + 41, "batch wire length sequence=%d got=%d expected=%d", sequence, len, expected_len + 41);
            if (len < 0 || len >= buf_len) break;
            TCHECK(de_cook(packet, len) == 0, "batch authentication sequence=%d", sequence);
            memcpy(expected, plain, expected_len);
            write_u32(expected, sequence);
            TCHECK(len == expected_len && memcmp(packet, expected, expected_len) == 0,
                   "batch order/content sequence=%d got=%u len=%d", sequence, read_u32(packet), len);
        }
        char extra[buf_len];
        TCHECK(recv(receiver, extra, sizeof(extra), MSG_DONTWAIT) == -1 && (errno == EAGAIN || errno == EWOULDBLOCK),
               "batch must deliver exactly 2*IO_BATCH_MAX+1 packets");
    }
    close(sender);
    close(receiver);
}

static void data_plane_selftest() {
    // process_arg's early --test-selftest dispatch skips normal parsing. Fork
    // to exercise the REAL deprecated flag and MTU parser without leaking its
    // globals/getopt state or the test key into the remaining selftests.
    fflush(NULL);
    for (int checksum_disabled = 0; checksum_disabled <= 1; checksum_disabled++) {
        pid_t child = fork();
        TCHECK(child >= 0, "data-plane fork");
        if (child == 0) {
            g_checks = g_failures = 0;
            char name[] = "data-plane-selftest", client[] = "-c";
            char local[] = "-l127.0.0.1:0", remote[] = "-r127.0.0.1:9";
            char key[] = "-k000102030405060708090a0b0c0d0e0f";
            char mtu[] = "--mtu", size[] = "2000", mode[] = "--mode", one[] = "1";
            char fec[] = "-f1:0", deprecated[] = "--disable-checksum";
            char *args[] = {name, client, local, remote, key, mtu, size, mode, one, fec, deprecated, NULL};
            optind = 0;
            process_arg(checksum_disabled ? 11 : 10, args);
            TCHECK(g_fec_par.mtu == 2000 && g_fec_par.mode == 1, "data-plane --mtu 2000 --mode 1 parsed");
            TCHECK(!disable_obscure && !disable_xor && key_string[0], "data-plane obscure and XOR enabled");
            iv_min = iv_max = 32;  // Force worst-case obscure padding, not luck.
            char payload[max_data_len];
            for (int i = 0; i < max_data_len; i++) payload[i] = (char)(i * 37);
            char *conv_packet = NULL;
            int conv_len = 0;
            TCHECK(put_conv(0x12345678, payload, sizeof(payload), conv_packet, conv_len) == 0 && conv_len == max_data_len + 4,
                   "data-plane max payload conv framing");
            struct ev_loop *loop = ev_loop_new(0);
            TCHECK(loop != NULL, "data-plane FEC loop");
            if (loop != NULL) {
                fec_encode_manager_t *encoder = new fec_encode_manager_t;
                encoder->set_loop_and_cb(loop, [](struct ev_loop *, ev_timer *, int) {});
                TCHECK(encoder->input(conv_packet, conv_len) == 0, "data-plane worst-case FEC input");
                int count = 0, *lengths = NULL;
                char **shards = NULL;
                TCHECK(encoder->output(count, shards, lengths) == 0 && count == 1, "data-plane FEC output");
                if (count == 1) {
                    TCHECK(lengths[0] == max_data_len + 14, "data-plane maximum pre-tag length must be 3614");
                    data_plane_auth_checks(shards[0], lengths[0]);
                    data_plane_batch_checks(shards[0]);
                }
                delete encoder;
                ev_loop_destroy(loop);
            }
            printf("data-plane selftest (--disable-checksum=%d, mtu=2000): %d checks, %d failures\n",
                   checksum_disabled, g_checks, g_failures);
            exit(g_failures ? 1 : 0);
        }
        if (child > 0) {
            int status = 0;
            pid_t waited;
            do { waited = waitpid(child, &status, 0); } while (waited < 0 && errno == EINTR);
            TCHECK(waited == child && WIFEXITED(status) && WEXITSTATUS(status) == 0,
                   "data-plane child --disable-checksum=%d status=%d", checksum_disabled, status);
        }
    }
}
