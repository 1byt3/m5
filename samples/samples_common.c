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

const char * const pkt_names[] = {
	NULL,
	"CONNECT",
	"CONNACK",
	"PUBLISH",
	"PUBACK",
	"PUBREC",
	"PUBREL",
	"PUBCOMP",
	"SUBSCRIBE",
	"SUBACK",
	"UNSUBSCRIBE",
	"UNSUBACK",
	"PINGREQ",
	"PINGRESP",
	"DISCONNECT",
	"AUTH" };

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

int tcp_accept(int server_fd, struct sockaddr_in *client_sa, int *client_fd)
{
	socklen_t len;
	int rc;

	rc = tcp_descriptor_ready(server_fd, D_READ);
	if (rc != 0) {
		return -1;
	}

	len = sizeof(*client_sa);
	*client_fd = accept(server_fd, (struct sockaddr *)client_sa, &len);
	if (*client_fd < 0 || len != sizeof(*client_sa)) {
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

int read_reply_msg(int fd,
		   int validate_packet(enum m5_pkt_type, void *msg, void *),
		   void *user_data)
{
	struct m5_topic topics[MAX_ARRAY_ELEMENTS];
	uint8_t rcodes[MAX_ARRAY_ELEMENTS];
	uint8_t out_data[MAX_BUF_SIZE];
	uint8_t in_data[MAX_BUF_SIZE];
	struct app_buf out = { .data = out_data, .size = sizeof(out_data) };
	struct app_buf in = { .data = in_data, .size = sizeof(in_data) };

	struct m5_pub_response msg_pub_response = { 0 };
	struct m5_subscribe msg_subscribe = { .topics = topics,
					      .size = MAX_ARRAY_ELEMENTS };
	struct m5_connect msg_connect = { 0 };
	struct m5_connack msg_connack = { 0 };
	struct m5_publish msg_publish = { 0 };
	struct m5_suback msg_suback = { 0 };
	struct m5_prop prop = { 0 };

	void *received_msg = NULL;
	struct m5_rc msg_rc = { 0 };
	uint8_t pkt_type;
	int rc;
	int i;

	rc = tcp_read(fd, &in);
	if (rc != 0) {
		DBG("tcp_read");
		goto lb_exit;
	}

lb_parse_another_packet:
	pkt_type = (*buf_current(&in) >> 4);

	switch (pkt_type) {
	default:
	case M5_PKT_RESERVED:
		DBG("invalid control packet");
		rc = -1;
		goto lb_exit;
	case M5_PKT_CONNECT:
		received_msg = &msg_connect;
		rc = m5_unpack_connect(NULL, &in, &msg_connect, &prop);
		break;
	case M5_PKT_CONNACK:
		received_msg = &msg_connack;
		rc = m5_unpack_connack(NULL, &in, &msg_connack, &prop);
		break;
	case M5_PKT_PUBLISH:
		received_msg = &msg_publish;
		rc = m5_unpack_publish(NULL, &in, &msg_publish, &prop);
		break;
	case M5_PKT_PUBACK:
		received_msg = &msg_pub_response;
		rc = m5_unpack_puback(NULL, &in, &msg_pub_response, &prop);
		break;
	case M5_PKT_PUBREC:
		received_msg = &msg_pub_response;
		rc = m5_unpack_pubrec(NULL, &in, &msg_pub_response, &prop);
		break;
	case M5_PKT_PUBREL:
		received_msg = &msg_pub_response;
		rc = m5_unpack_pubrel(NULL, &in, &msg_pub_response, &prop);
		break;
	case M5_PKT_PUBCOMP:
		received_msg = &msg_pub_response;
		rc = m5_unpack_pubcomp(NULL, &in, &msg_pub_response, &prop);
		break;
	case M5_PKT_SUBSCRIBE:
		received_msg = &msg_subscribe;
		rc = m5_unpack_subscribe(NULL, &in, &msg_subscribe, &prop);
		break;
	case M5_PKT_SUBACK:
		received_msg = &msg_suback;
		rc = m5_unpack_suback(NULL, &in, &msg_suback, &prop);
		break;
	case M5_PKT_UNSUBSCRIBE:
		received_msg = &msg_subscribe;
		rc = m5_unpack_unsubscribe(NULL, &in, &msg_subscribe);
		break;
	case M5_PKT_UNSUBACK:
		received_msg = &msg_suback;
		rc = m5_unpack_unsuback(NULL, &in, &msg_suback, &prop);
		break;
	case M5_PKT_PINGREQ:
		rc = m5_unpack_pingreq(NULL, &in);
		break;
	case M5_PKT_PINGRESP:
		rc = m5_unpack_pingresp(NULL, &in);
		break;
	case M5_PKT_DISCONNECT:
		received_msg = &msg_rc;
		rc = m5_unpack_disconnect(NULL, &in, &msg_rc, &prop);
		break;
	case M5_PKT_AUTH:
		received_msg = &msg_rc;
		rc = m5_unpack_auth(NULL, &in, &msg_rc, &prop);
		break;
	}

	printf("Received: %s\n", pkt_names[pkt_type]);

	if (rc != 0) {
		printf("Msg: %d\n", pkt_type);
		DBG("unpack");
		goto lb_exit;
	}

	if (validate_packet != NULL) {
		rc = validate_packet(pkt_type, received_msg, user_data);
		if (rc != 0) {
			DBG("validate_packet");
			goto lb_exit;
		}
	}

	buf_reset(&out);

	switch (pkt_type) {
	default:
	case M5_PKT_RESERVED:
	case M5_PKT_CONNACK:
	case M5_PKT_PUBACK:
	case M5_PKT_PUBCOMP:
	case M5_PKT_SUBACK:
	case M5_PKT_UNSUBACK:
	case M5_PKT_PINGRESP:
	case M5_PKT_DISCONNECT:
		break;
	case M5_PKT_CONNECT:
		msg_connack.session_present = 0;
		msg_connack.return_code = 0;
		printf("Sending: %s\n", pkt_names[M5_PKT_CONNACK]);
		rc = m5_pack_connack(NULL, &out, &msg_connack, NULL);
		break;
	case M5_PKT_PUBLISH:
		msg_pub_response.packet_id = msg_publish.packet_id;
		msg_pub_response.reason_code = M5_RC_SUCCESS;
		switch ((enum m5_qos)msg_publish.qos) {
		case M5_QoS0:
			break;
		case M5_QoS1:
			printf("Sending: %s\n", pkt_names[M5_PKT_PUBACK]);
			rc = m5_pack_puback(NULL, &out,
					    &msg_pub_response, NULL);
			break;
		case M5_QoS2:
			printf("Sending: %s\n", pkt_names[M5_PKT_PUBREC]);
			rc = m5_pack_pubrec(NULL, &out,
					    &msg_pub_response, NULL);
			break;
		}
		break;
	case M5_PKT_PUBREC:
		printf("Sending: %s\n", pkt_names[M5_PKT_PUBREL]);
		rc = m5_pack_pubrel(NULL, &out,
				    &msg_pub_response, NULL);
		break;
	case M5_PKT_PUBREL:
		printf("Sending: %s\n", pkt_names[M5_PKT_PUBCOMP]);
		rc = m5_pack_pubcomp(NULL, &out,
				     &msg_pub_response, NULL);
		break;
	case M5_PKT_SUBSCRIBE:
	case M5_PKT_UNSUBSCRIBE:
		if (msg_subscribe.items > sizeof(rcodes)) {
			DBG("subscribe items > msg_suback.rc_size");
			rc = -1;
			goto lb_exit;
		}
		for (i = 0; i < msg_subscribe.items; i++) {
			uint8_t qos = msg_subscribe.topics[i].options & 0x03;

			rcodes[i] = qos;
		}

		msg_suback.packet_id = msg_subscribe.packet_id;
		msg_suback.rc_size = msg_subscribe.items;
		msg_suback.rc_items = msg_subscribe.items;
		msg_suback.rc = rcodes;
		if (pkt_type == M5_PKT_SUBSCRIBE) {
			printf("Sending: %s\n", pkt_names[M5_PKT_SUBACK]);
			rc = m5_pack_suback(NULL, &out, &msg_suback, NULL);

			printf("RC: %d\n", rc);


		} else {
			printf("Sending: %s\n", pkt_names[M5_PKT_UNSUBACK]);
			rc = m5_pack_unsuback(NULL, &out, &msg_suback, NULL);
		}
		break;
	case M5_PKT_PINGREQ:
		printf("Sending: %s\n", pkt_names[M5_PKT_PINGRESP]);
		rc = m5_pack_pingresp(NULL, &out);
		break;
	case M5_PKT_AUTH:
		printf("Sending: %s\n", pkt_names[M5_PKT_AUTH]);
		rc = m5_pack_auth(NULL, &out, 0x00, NULL);
		break;
	}

	if (rc != 0) {
		DBG("pack response");
		goto lb_exit;
	}

	if (out.len > 0) {
		rc = tcp_write(fd, &out);
		if (rc != 0) {
			DBG("tcp_write");
			goto lb_exit;
		}
	}

	if (buf_bytes_to_read(&in) > 0) {
		/* more data to parse */
		goto lb_parse_another_packet;
	}

	rc = 0;

lb_exit:
	return rc;
}

