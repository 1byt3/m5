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
#include <sys/time.h>
#include <unistd.h>

#if defined(__FreeBSD__)
#include <sys/endian.h>
#else
#include <endian.h>
#endif

#include <string.h>

enum descriptor_op {
	D_READ,
	D_WRITE,
};


static int rx_tx_timeout = 5; /* seconds */

void set_tcp_timeout(int timeout)
{
	rx_tx_timeout = timeout;
}

static int tcp_descriptor_ready(int fd, enum descriptor_op type)
{
	struct timeval timeout;
	fd_set set;
	int rc;

	timeout.tv_sec = rx_tx_timeout;
	timeout.tv_usec = 0;

	FD_ZERO(&set);
	FD_SET(fd, &set);

	rc = select(FD_SETSIZE,
		    type == D_READ ? &set : NULL,
		    type == D_WRITE ? &set : NULL,
		    NULL,
		    &timeout);
	if (rc <= 0) {
		return -1;
	}

	return 0;
}

int tcp_read(int fd, struct app_buf *buf)
{
	ssize_t read_bytes;
	int rc;

	rc = tcp_descriptor_ready(fd, D_READ);
	if (rc != 0) {
		return -1;
	}

	buf_reset(buf);
	read_bytes = read(fd, buf->data, buf->size);
	if (read_bytes <= 0) {
		DBG("read");
		return -1;
	}

	buf->len = read_bytes;

	return 0;
}

int tcp_write(int fd, struct app_buf *buf)
{
	ssize_t written_bytes;
	int rc;

	rc = tcp_descriptor_ready(fd, D_WRITE);
	if (rc != 0) {
		return -1;
	}

	written_bytes = write(fd, buf->data, buf->len);
	if (written_bytes <= 0 || (size_t)written_bytes != buf->len) {
		DBG("write");
		return -1;
	}

	return 0;
}

int tcp_listen(uint8_t server_addr[4], uint16_t port, int backlog,
	       int *server_fd)
{
	struct sockaddr_in sa = { 0 };
	uint32_t addr;
	int rc = -1;

	*server_fd = socket(AF_INET, SOCK_STREAM, 0);
	if (*server_fd < 0) {
		DBG("socket");
		goto lb_exit;
	}

	addr = (server_addr[0] << 24) | (server_addr[1] << 16) |
	       (server_addr[2] << 8) | server_addr[3];
	sa.sin_family = AF_INET;
	sa.sin_port = htobe16(port);
	sa.sin_addr.s_addr = htobe32(addr);

	rc = bind(*server_fd, (struct sockaddr *)&sa, sizeof(sa));
	if (rc != 0) {
		DBG("bind");
		goto lb_close;
	}

	rc = listen(*server_fd, backlog);
	if (rc != 0) {
		DBG("listen");
		goto lb_close;
	}

	return 0;

lb_close:
	tcp_disconnect(*server_fd);

lb_exit:
	return rc;
}

int tcp_accept(int server_fd, struct sockaddr_in *sa, int *client_fd)
{
	socklen_t len;
	int rc;

	rc = tcp_descriptor_ready(server_fd, D_READ);
	if (rc != 0) {
		return -1;
	}

	len = sizeof(*sa);
	*client_fd = accept(server_fd, (struct sockaddr *)sa, &len);
	if (*client_fd < 0 || len != sizeof(*sa)) {
		return -1;
	}

	return 0;
}

int tcp_connect(int *socket_fd, uint8_t peer[4], uint16_t peer_port)
{
	struct sockaddr_in sa = { 0 };
	uint32_t addr;
	int rc = -1;

	*socket_fd = socket(AF_INET, SOCK_STREAM, 0);
	if (*socket_fd < 0) {
		DBG("socket");
		goto lb_exit;
	}

	addr = (peer[0] << 24) | (peer[1] << 16) | (peer[2] << 8) | peer[3];
	sa.sin_family = AF_INET;
	sa.sin_port = htobe16(peer_port);
	sa.sin_addr.s_addr = htobe32(addr);

	rc = connect(*socket_fd, (struct sockaddr *)&sa, sizeof(sa));
	if (rc != 0) {
		DBG("connect");
		goto lb_close;
	}

	return 0;

lb_close:
	close(*socket_fd);

lb_exit:
	return rc;
}

void tcp_disconnect(int socket_fd)
{
	close(socket_fd);
}

int client_connect(int *socket_fd, const char *client_id,
		   uint8_t peer_addr[4], uint16_t peer_port)
{
	struct m5_connect msg_connect = { .client_id = (uint8_t *)client_id,
					  .client_id_len = strlen(client_id),
					  .keep_alive = 0, };
	static uint8_t data[MAX_BUF_SIZE] = { 0 };
	struct app_buf buf = { .data = data,
			       .size = sizeof(data) };
	struct m5_connack msg_connack = { 0 };
	struct m5_prop prop = { 0 };

	int rc;

	printf("TCP connect\n");
	rc = tcp_connect(socket_fd, peer_addr, peer_port);
	if (rc != 0) {
		DBG("tcp_connect");
		goto lb_error;
	}

	printf("Sending: CONNECT\n");
	rc = pack_msg_write(*socket_fd, M5_PKT_CONNECT, &msg_connect);
	if (rc != 0) {
		DBG("pack_msg_write CONNECT");
		goto lb_error_disconnect;
	}

	rc = tcp_read(*socket_fd, &buf);
	if (rc != 0) {
		DBG("tcp_read");
		goto lb_error_disconnect;
	}

	rc = m5_unpack_connack(NULL, &buf, &msg_connack, &prop);
	if (rc != M5_SUCCESS || msg_connack.return_code != M5_RC_SUCCESS) {
		DBG("m5_unpack_connack");
		goto lb_error_disconnect;
	}
	printf("Received: CONNACK\n");

	return 0;

lb_error_disconnect:
	tcp_disconnect(*socket_fd);

lb_error:
	return -1;
}

int pack_msg_write(int socket_fd, enum m5_pkt_type type, void *msg)
{
	static uint8_t data[MAX_BUF_SIZE];
	struct app_buf buf = { .data = data, .size = sizeof(data) };
	int rc;

	switch (type) {
	default:
		DBG("unexpected packet type");
		goto lb_error;
	case M5_PKT_PUBLISH:
		rc = m5_pack_publish(NULL, &buf,
				     (struct m5_publish *)msg, NULL);
		break;
	case M5_PKT_PUBREL:
		rc = m5_pack_pubrel(NULL, &buf,
				    (struct m5_pub_response *)msg, NULL);
		break;
	case M5_PKT_PINGRESP:
		rc = m5_pack_pingresp(NULL, &buf);
		break;
	case M5_PKT_CONNECT:
		rc = m5_pack_connect(NULL, &buf,
				     (struct m5_connect *)msg, NULL);
	}

	if (rc != M5_SUCCESS) {
		DBG("pack");
		goto lb_error;
	}

	rc = tcp_write(socket_fd, &buf);
	if (rc != 0) {
		DBG("tcp_write");
		goto lb_error;
	}

	return 0;

lb_error:
	return -1;
}

