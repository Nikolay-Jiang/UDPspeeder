#include "common.h"
#include "log.h"

#include "lib/rs.h"
#include "packet.h"
#include "connection.h"
#include "fd_manager.h"
#include "delay_manager.h"
#include "fec_manager.h"
#include "misc.h"
#include "tunnel.h"
#include "test_mode.h"
//#include "tun_dev.h"
#include "git_version.h"
using namespace std;

static void print_help() {
    char git_version_buf[100] = {0};
    strncpy(git_version_buf, gitversion, 10);

    printf("UDPspeeder V2\n");
    printf("git version: %s    ", git_version_buf);
    printf("build date: %s %s\n", __DATE__, __TIME__);
    printf("repository: https://github.com/wangyu-/UDPspeeder\n");
    printf("\n");
    printf("usage:\n");
    printf("    run as client: ./this_program -c -l local_listen_ip:local_port -r server_ip:server_port  [options]\n");
    printf("    run as server: ./this_program -s -l server_listen_ip:server_port -r remote_ip:remote_port  [options]\n");
    printf("    ipv6 addresses use bracket form everywhere an address is accepted, e.g. -l\"[::]:4096\" -r\"[2001:db8::1]:4096\"\n");
    printf("\n");
    printf("common options, must be same on both sides:\n");
    printf("    -k,--key              <string>        key for simple xor encryption. if not set, xor is disabled\n");

    printf("main options:\n");
    printf("    -f,--fec              x:y             forward error correction, send y redundant packets for every x packets\n");
    printf("    --timeout             <number>        how long could a packet be held in queue before doing fec, unit: ms, default: 8ms\n");
    printf("    --report              <number>        turn on send/recv report, and set a period for reporting, unit: s\n");

    printf("advanced options:\n");
    printf("    --mode                <number>        fec-mode,available values: 0,1; mode 0(default) costs less bandwidth,no mtu problem.\n");
    printf("                                          mode 1 usually introduces less latency, but you have to care about mtu.\n");
    printf("    --mtu                 <number>        mtu. for mode 0, the program will split packet to segment smaller than mtu value.\n");
    printf("                                          for mode 1, no packet will be split, the program just check if the mtu is exceed.\n");
    printf("                                          default value: 1250. you typically shouldnt change this value.\n");
    printf("    -j,--jitter           <number>        simulated jitter. randomly delay first packet for 0~<number> ms, default value: 0.\n");
    printf("                                          do not use if you dont know what it means.\n");
    printf("    -i,--interval         <number>        scatter each fec group to a interval of <number> ms, to defend burst packet loss.\n");
    printf("                                          default value: 0. do not use if you dont know what it means.\n");
    printf("    -f,--fec              x1:y1,x2:y2,..  similiar to -f/--fec above,fine-grained fec parameters,may help save bandwidth.\n");
    printf("                                          example: \"-f 1:3,2:4,10:6,20:10\". check repo for details\n");
    printf("    --random-drop         <number>        simulate packet loss, unit: 0.01%%. default value: 0.\n");
    printf("    --disable-obscure     <number>        disable obscure, to save a bit bandwidth and cpu\n");
    printf("    --disable-checksum    <number>        disable checksum to save a bit bandwdith and cpu\n");
    // printf("    --disable-xor         <number>        disable xor\n");

    printf("developer options:\n");
    printf("    --fifo                <string>        use a fifo(named pipe) for sending commands to the running program, so that you\n");
    printf("                                          can change fec encode parameters dynamically, check readme.md in repository for\n");
    printf("                                          supported commands.\n");
    printf("    -j ,--jitter          jmin:jmax       similiar to -j above, but create jitter randomly between jmin and jmax\n");
    printf("    -i,--interval         imin:imax       similiar to -i above, but scatter randomly between imin and imax\n");
    printf("    -q,--queue-len        <number>        fec queue len, only for mode 0, fec will be performed immediately after queue is full.\n");
    printf("                                          default value: 200. \n");
    printf("    --decode-buf          <number>        size of buffer of fec decoder,unit: packet, default: 2000\n");
    //    printf("    --fix-latency         <number>        try to stabilize latency, only for mode 0\n");
    printf("    --delay-capacity      <number>        max number of delayed packets, 0 means unlimited, default: 0\n");
    printf("    --disable-fec         <number>        completely disable fec, turn the program into a normal udp tunnel\n");
    printf("    --sock-buf            <number>        buf size for socket, >=10 and <=10240, unit: kbyte, default: 1024\n");
    printf("    --out-addr            ip:port         force all output packets of '-r' end to go through this address, port 0 for random port.\n");
    printf("                                          for ipv6 use bracket form, e.g. [::1]:0. must be the same address family as the peer;\n");
    printf("                                          in --port-range-mode the port must be 0.\n");
#ifdef __linux__
    printf("    --out-interface       <string>        force all output packets of '-r' end to go through this interface.\n");
#endif
    printf("port-range mode options (spread the tunnel across N udp ports to defeat per-flow isp rate limiting):\n");
    printf("    --port-range-mode                     enable port-range mode. must be set on both sides. off by default.\n");
    printf("    --control-port        <port>          (server) fixed control/handshake port.\n");
    printf("    --data-port-range     a-b             (server) inclusive range of data ports, 1..256 ports.\n");
    printf("    --control-host        ip:port         (client) server's control address to handshake with.\n");
    printf("    --control-mac         legacy|siphash   control-plane mac. must match on both sides. default: legacy.\n");
    printf("    --nat-keepalive       <sec>           (server) nat endpoint keepalive, default: 30.\n");
    printf("    --hello-retry-max     <sec>           (client) max handshake retry backoff, default: 30.\n");
    printf("    --heartbeat-interval  <sec>           control-plane heartbeat interval, default: 5.\n");
    printf("    --heartbeat-loss-threshold <n>        missed heartbeats before re-handshake, default: 3.\n");
    printf("      NOTE: in port-range mode the server identifies a client by source ip only (the source port\n");
    printf("            is ignored), so clients behind a symmetric nat work. the trade-off is that only ONE\n");
    printf("            client per public ip is supported -- two clients sharing an ip collapse into one\n");
    printf("            session. use a separate ip, or a separate server instance, for each client.\n");

    printf("test mode options (measure the link and recommend fec parameters):\n");
    printf("    --test-mode                           run a one-shot link measurement instead of a tunnel, then exit.\n");
    printf("                                          must be set on both sides. -k is mandatory: probes are mac-authenticated,\n");
    printf("                                          so an open responder cant be driven by an unauthenticated peer. the\n");
    printf("                                          server -> client phases additionally need a per-session cookie handed\n");
    printf("                                          out in the handshake, so a spoofed source address cant aim them at a\n");
    printf("                                          third party even with the key.\n");
    printf("                                          responder: -s --test-mode -l <ip:port>\n");
    printf("                                          prober:    -c --test-mode -r <ip:port>  (prints the report)\n");
    printf("    --test-duration       <sec>           per-phase probe duration, default: 30, max: 600.\n");
    printf("    --test-pps            <number>        probe packet rate, default: 200, max: 20000.\n");
    printf("    --test-pkt-size       <number>        probe packet size, default: 1200, min: 64, max: 1400. prober-side only:\n");
    printf("                                          it is carried in the handshake, so both directions are measured at it.\n");
    printf("    --test-app-mbps       <number>        your real payload rate, used to convert redundancy overhead into\n");
    printf("                                          absolute bandwidth. default: the probe rate itself.\n");
    printf("    --test-no-reverse                     skip the server -> client phases. only needed on the prober;\n");
    printf("                                          the responder always supports them.\n");
    printf("    --test-selftest                       run the evaluators built-in self-checks against synthetic traces\n");
    printf("                                          and exit; no network involved.\n");
    printf("    --data-port-range     a-b             optional, same flag as above: when set on both sides, also probes\n");
    printf("                                          upstream traffic spread across the n ports and reports whether\n");
    printf("                                          port-range mode would reduce loss on this link. it must be\n");
    printf("                                          identical on both ends (or absent from both); a mismatch is\n");
    printf("                                          detected during the handshake and the session is refused.\n");
    printf("      NOTE: --test-pps x --test-duration must not exceed 500000 probes per phase; the\n");
    printf("            combination is validated at startup.\n");
    printf("      NOTE: both directions are measured; the report gives a separate -f/-i for each\n");
    printf("            end, because -f is per-direction and links are often asymmetric. total\n");
    printf("            runtime is the fixed 30s rate scan plus two --test-duration passes, plus\n");
    printf("            two more if --data-port-range is set (about 30s + 2x or 4x). the rate\n");
    printf("            scan itself only probes client -> server, so a link policed ONLY on the\n");
    printf("            server -> client direction will not be detected as policed.\n");

    printf("log and help options:\n");
    printf("    --log-level           <number>        0: never    1: fatal   2: error   3: warn \n");
    printf("                                          4: info (default)      5: debug   6: trace\n");
    printf("    --log-position                        enable file name, function name, line number in log\n");
    printf("    --disable-color                       disable log color\n");
    printf("    -h,--help                             print this help message\n");

    // printf("common options,these options must be same on both side\n");
}

void sigpipe_cb(struct ev_loop *l, ev_signal *w, int revents) {
    mylog(log_info, "got sigpipe, ignored");
}

void sigterm_cb(struct ev_loop *l, ev_signal *w, int revents) {
    mylog(log_info, "got sigterm, exit");
    myexit(0);
}

void sigint_cb(struct ev_loop *l, ev_signal *w, int revents) {
    mylog(log_info, "got sigint, exit");
    myexit(0);
}

int main(int argc, char *argv[]) {
    working_mode = tunnel_mode;
    init_ws();
    // unit_test();

    struct ev_loop *loop = ev_default_loop(0);
    ev_signal signal_watcher_sigpipe;
    ev_signal_init(&signal_watcher_sigpipe, sigpipe_cb, SIGPIPE);
    ev_signal_start(loop, &signal_watcher_sigpipe);

    ev_signal signal_watcher_sigterm;
    ev_signal_init(&signal_watcher_sigterm, sigterm_cb, SIGTERM);
    ev_signal_start(loop, &signal_watcher_sigterm);

    ev_signal signal_watcher_sigint;
    ev_signal_init(&signal_watcher_sigint, sigint_cb, SIGINT);
    ev_signal_start(loop, &signal_watcher_sigint);

    assert(sizeof(u64_t) == 8);
    assert(sizeof(i64_t) == 8);
    assert(sizeof(u32_t) == 4);
    assert(sizeof(i32_t) == 4);
    assert(sizeof(u16_t) == 2);
    assert(sizeof(i16_t) == 2);
    dup2(1, 2);  // redirect stderr to stdout
    int i, j, k;

    if (argc == 1) {
        print_help();
        myexit(-1);
    }
    for (i = 0; i < argc; i++) {
        if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            print_help();
            myexit(0);
        }
    }

    process_arg(argc, argv);

    delay_manager.set_capacity(delay_capacity);

    if (strlen(tun_dev) == 0) {
        sprintf(tun_dev, "tun%u", get_fake_random_number() % 1000);
    }

    if (working_mode == test_working_mode) {
        if (program_mode == client_mode) {
            test_mode_prober_loop();
        } else {
            test_mode_responder_loop();
        }
    } else if (program_mode == client_mode) {
        tunnel_client_event_loop();
    } else {
        tunnel_server_event_loop();
    }

    return 0;
}
