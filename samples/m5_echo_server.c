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

#include "samples_common.h"

#include <sys/types.h>

#if defined(__FreeBSD__)
#include <sys/endian.h>
#else
#include <endian.h>
#endif

#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <signal.h>

#define SERVER_ADDR	{ 127, 0, 0, 1 }
#define SERVER_PORT	1863

#define LISTEN_BACKLOG	1

static int loop_forever = 1;

static int echo_server(void)
{
	uint8_t server_addr[] = SERVER_ADDR;
	int server_fd;
	int rc;

	rc = tcp_listen(server_addr, SERVER_PORT, LISTEN_BACKLOG, &server_fd);
	if (rc != 0) {
		DBG("tcp_listen");
		goto lb_exit;
	}

	while (loop_forever != 0) {
		struct sockaddr_in client_sa = { 0 };
		int client_fd;

		printf("Waiting for connections [CTRL + C to quit]\n");
		rc = tcp_accept(server_fd, &client_sa, &client_fd);
		if (rc != 0) {
			continue;
		}

		do {
			rc = read_reply_msg(client_fd, NULL, NULL);
		} while (rc == 0 && loop_forever != 0);

		tcp_disconnect(client_fd);
		printf("Connection closed\n");
	}

	tcp_disconnect(server_fd);
	rc = 0;

lb_exit:
	return rc;
}

static void signal_handler(int id)
{
	(void)id;

	printf("\n\t\tBye!\n\n");
	loop_forever = 0;
}

int main(void)
{
	set_tcp_timeout(60); /* seconds */

	signal(SIGPIPE, signal_handler);
	signal(SIGTERM, signal_handler);
	signal(SIGINT, signal_handler);

	return echo_server();
}

