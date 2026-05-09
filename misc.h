/*
 * misc.h
 *
 *  Created on: Oct 26, 2017
 *      Author: root
 */

#ifndef MISC_H_
#define MISC_H_

#include "common.h"
#include "connection.h"
#include "fd_manager.h"
#include "delay_manager.h"
#include "fec_manager.h"
#include "port_range_manager.h"

extern char fifo_file[1000];

extern int mtu_warn;

extern int disable_mtu_warn;
extern int disable_fec;
extern int disable_checksum;

extern int debug_force_flush_fec;

extern int jitter_min;
extern int jitter_max;

extern int output_interval_min;
extern int output_interval_max;

extern int fix_latency;

// extern u32_t local_ip_uint32,remote_ip_uint32;
// extern char local_ip[100], remote_ip[100];
// extern int local_port, remote_port;

extern address_t local_addr, remote_addr;

extern address_t *out_addr;
extern char *out_interface;

extern conn_manager_t conn_manager;
extern delay_manager_t delay_manager;
extern fd_manager_t fd_manager;

extern int time_mono_test;

extern int delay_capacity;
extern int io_batch_size;

extern int keep_reconnect;

// port-range mode
extern int port_range_mode;
extern int ctrl_port;
extern int ctrl_mac_mode;
extern int nat_keepalive_sec;
extern int hello_retry_max_sec;
extern int heartbeat_interval_sec;
extern int heartbeat_loss_threshold;
extern address_t ctrl_addr;
extern char data_port_range_str[64];
extern port_range_manager_t port_range_mgr;

extern int tun_mtu;

extern int mssfix;

extern int manual_set_tun;
extern int persist_tun;

int from_normal_to_fec(conn_info_t &conn_info, char *data, int len, int &out_n, char **&out_arr, int *&out_len, my_time_t *&out_delay);
int from_fec_to_normal(conn_info_t &conn_info, char *data, int len, int &out_n, char **&out_arr, int *&out_len, my_time_t *&out_delay);

int delay_send(my_time_t delay, const dest_t &dest, char *data, int len);
int print_parameter();
int handle_command(char *s);

int unit_test();

// void print_help();

void process_arg(int argc, char *argv[]);

extern char sub_net[100];
extern u32_t sub_net_uint32;
extern char tun_dev[100];

#endif /* MISC_H_ */
