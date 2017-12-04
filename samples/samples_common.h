/*
 *                                   1byt3
 *
 *                              License Notice
 *
 * 1byt3 provides a commercial license agreement for this software. This
 * commercial license can be used for development of proprietary/commercial
 * software. Under this commercial license you do not need to comply with the
 * terms of the GNU Affero General Public License, either version 3 of the
 * License, or (at your option) any later version.
 *
 * If you don't receive a commercial license from us (1byt3), you MUST assume
 * that this software is distributed under the GNU Affero General Public
 * License, either version 3 of the License, or (at your option) any later
 * version.
 *
 * Contact us for additional information: customers at 1byt3.com
 *
 *                          End of License Notice
 */

/*
 * m5: MQTT 5 Low Level Packet Library
 *
 * Copyright (C) 2017 1byt3, customers at 1byt3.com
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef __SAMPLES_COMMON_H__
#define __SAMPLES_COMMON_H__

#include "m5.h"

#include <sys/socket.h>
#include <netinet/in.h>
#include <stdio.h>

#define MAX_BUF_SIZE		128
#define MAX_ARRAY_ELEMENTS	16

#define DBG(msg)	\
		fprintf(stderr, "[%s:%d] %s\n", __func__, __LINE__, msg)

void set_tcp_timeout(int timeout);

int tcp_read(int fd, struct app_buf *buf);

int tcp_write(int fd, struct app_buf *buf);

int tcp_accept(int server_fd, struct sockaddr_in *sa, int *client_fd);

int tcp_connect(int *socket_fd, uint8_t peer[4], uint16_t peer_port);

void tcp_disconnect(int socket_fd);

int client_connect(int *socket_fd, const char *client_id,
		   uint8_t peer_addr[4], uint16_t peer_port);

int pack_msg_write(int socket_fd, enum m5_pkt_type type, void *msg);

#endif

