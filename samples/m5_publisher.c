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

#include "m5.h"

#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/time.h>

#if defined(__FreeBSD__)
#include <sys/endian.h>
#else
#include <endian.h>
#endif

#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <signal.h>
#include <stdio.h>

#define PEER_ADDR	{ 127, 0, 0, 1 }
#define PEER_PORT	1863

#define RX_TX_TIMEOUT	5 /* seconds */

#define CLIENT_ID	"m5_publisher"
#define TOPIC_NAME	"greetings"
#define PAYLOAD		"Hello, World!"

#define DBG(msg)	\
		fprintf(stderr, "[%s:%d] %s\n", __func__, __LINE__, msg)

static int loop_forever = 1;

static int tcp_connect(int *socket_fd)
{
	struct sockaddr_in sa = { 0 };
	uint8_t peer[] = PEER_ADDR;
	uint32_t addr;
	int rc = -1;

	*socket_fd = socket(AF_INET, SOCK_STREAM, 0);
	if (*socket_fd < 0) {
		DBG("socket");
		goto lb_exit;
	}

	addr = (peer[0] << 24) | (peer[1] << 16) | (peer[2] << 8) | peer[3];
	sa.sin_family = AF_INET;
	sa.sin_port = htobe16(PEER_PORT);
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

static void tcp_disconnect(int socket_fd)
{
	close(socket_fd);
}

static ssize_t tcp_read(int socket_fd, struct app_buf *buf)
{
	struct timeval timeout;
	ssize_t read_bytes;
	fd_set set;
	int rc;

	timeout.tv_sec = RX_TX_TIMEOUT;
	timeout.tv_usec = 0;

	FD_ZERO(&set);
	FD_SET(socket_fd, &set);

	rc = select(FD_SETSIZE, &set, NULL, NULL, &timeout);
	if (rc <= 0) {
		DBG("read timeout");
		return -1;
	}

	buf_reset(buf);
	read_bytes = read(socket_fd, buf->data, buf->size);
	if (read_bytes <= 0) {
		DBG("read error");
		return -1;
	}

	buf->len = read_bytes;

	return 0;
}

static int tcp_write(int socket_fd, struct app_buf *buf)
{
	struct timeval timeout;
	ssize_t written_bytes;
	fd_set set;
	int rc;

	timeout.tv_sec = RX_TX_TIMEOUT;
	timeout.tv_usec = 0;

	FD_ZERO(&set);
	FD_SET(socket_fd, &set);

	rc = select(FD_SETSIZE, NULL, &set, NULL, &timeout);
	if (rc <= 0) {
		DBG("write timeout");
		return -1;
	}

	written_bytes = write(socket_fd, buf->data, buf->len);
	if (written_bytes <= 0 || (size_t)written_bytes != buf->len) {
		DBG("write");
		return -1;
	}

	return 0;
}

static int pack_msg_write(int socket_fd, enum m5_pkt_type type, void *msg)
{
	static uint8_t data[128];
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

static int publisher_next_state(int current_state, enum m5_qos qos)
{
	int state = (current_state << 4) | qos;

	switch (state) {
	case ((M5_PKT_PUBLISH << 4) | M5_QoS0):
		return M5_PKT_RESERVED;
	case ((M5_PKT_PUBLISH << 4) | M5_QoS1):
		return M5_PKT_PUBACK;
	case ((M5_PKT_PUBACK << 4) | M5_QoS1):
		/* PUBLISH QoS 1 handshake completed */
		return M5_PKT_RESERVED;
	case ((M5_PKT_PUBLISH << 4) | M5_QoS2):
		return M5_PKT_PUBREC;
	case ((M5_PKT_PUBREC << 4) | M5_QoS2):
		return M5_PKT_PUBREL;
	case ((M5_PKT_PUBREL << 4) | M5_QoS2):
		return M5_PKT_PUBCOMP;
	case ((M5_PKT_PUBCOMP << 4) | M5_QoS2):
		/* PUBLISH QoS 2 handshake completed */
		return M5_PKT_RESERVED;
	default:
		return -1;
	}
}

static int publisher_connect(int *socket_fd)
{
	struct m5_connect msg_connect = { .client_id = (uint8_t *)CLIENT_ID,
					  .client_id_len = strlen(CLIENT_ID),
					  .keep_alive = 0, };
	static uint8_t data[128] = { 0 };
	struct app_buf buf = { .data = data,
			       .size = sizeof(data) };
	struct m5_connack msg_connack = { 0 };
	struct m5_prop prop = { 0 };
	int rc;

	printf("TCP connect\n");
	rc = tcp_connect(socket_fd);
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

/*
 * --This-- publisher application can only receive the PUBLISH-related
 * control packets and also the PINGREQ control packet.
 *
 * Given that the "PUBLISH" action is initialized by this application,
 * the starting state is PUBLISH.
 *
 * Depending on the QoS value, the response may be PUBACK or PUBREC.
 * After PUBREC is received, PUBREL is sent and PUBCOMP is expected.
 * Between those PUB{ACK, REC, COMP} packets, the PINGREQ control
 * packet may be received.
 *
 * The m5 library supports multiple packets in the same TCP stream
 * (multi-frame approach), via the struct m5_app_buf, so we must check
 * if the buffer is fully parsed before exiting this routine.
 */

static int read_pub_response(int socket_fd, int packet_id, enum m5_qos qos)
{
	static uint8_t data[32];
	struct app_buf buf = { .data = data, .size = sizeof(data) };

	int current_state = M5_PKT_PUBLISH;
	struct m5_pub_response msg = { 0 };
	struct m5_prop prop = { 0 };
	uint8_t pkt_type;
	int next;
	int rc;

lb_start:
	buf_reset(&buf);
	rc = tcp_read(socket_fd, &buf);
	if (rc != 0) {
		DBG("tcp_read");
		goto lb_error;
	}

lb_parse_another_packet:
	pkt_type = (*buf_current(&buf) >> 4);

	next = publisher_next_state(current_state, qos);
	if (next != pkt_type && pkt_type != M5_PKT_PINGREQ) {
		DBG("unexpected control packet received");
		goto lb_error;
	}

	switch (pkt_type) {
	default:
		goto lb_error;
	case M5_PKT_PINGREQ:
		printf("Received: PINGREQ\n");
		rc = m5_unpack_pingreq(NULL, &buf);
		if (rc != 0) {
			DBG("m5_unpack_pingreq");
			goto lb_error;
		}

		printf("Sending: PINGRESP\n");
		rc = pack_msg_write(socket_fd, M5_PKT_PINGRESP, NULL);
		if (rc != 0) {
			DBG("write_pingresp");
			goto lb_error;
		}
		break;
	case M5_PKT_PUBACK:
		printf("Received: PUBACK\n");
		rc = m5_unpack_puback(NULL, &buf, &msg, &prop);
		if (rc != 0) {
			DBG("m5_unpack_puback");
			goto lb_error;
		}
		current_state = M5_PKT_PUBACK;
		break;
	case M5_PKT_PUBREC:
		printf("Received: PUBREC\n");
		rc = m5_unpack_pubrec(NULL, &buf, &msg, &prop);
		if (rc != M5_SUCCESS) {
			DBG("m5_unpack_pubrec");
			goto lb_error;
		}

		if (msg.packet_id != packet_id) {
			DBG("invalid packet id received");
			goto lb_error;
		}

		printf("Sending: PUBREL\n");
		rc = pack_msg_write(socket_fd, M5_PKT_PUBREL, &msg);
		if (rc != 0) {
			DBG("tcp_write");
			goto lb_error;
		}
		/* wait for PUBCOMP */
		current_state = M5_PKT_PUBREL;
		goto lb_start;
	case M5_PKT_PUBCOMP:
		printf("Received: PUBCOMP\n");
		rc = m5_unpack_pubcomp(NULL, &buf, &msg, &prop);
		if (rc != M5_SUCCESS) {
			DBG("m5_unpack_pubrec");
			goto lb_error;
		}

		if (msg.packet_id != packet_id) {
			DBG("invalid packet id received");
			goto lb_error;
		}
		current_state = M5_PKT_PUBCOMP;
		break;
	}

	if (buf_bytes_to_read(&buf) > 0) {
		/* more data to parse */
		goto lb_parse_another_packet;
	}

	/* Reserved == nothing else to do */
	if (publisher_next_state(current_state, qos) != M5_PKT_RESERVED) {
		/* PUBLISH handshake not yet finished */
		goto lb_start;
	}

	return 0;

lb_error:
	return -1;
}

static int publish_msg(int socket_fd, enum m5_qos qos)
{
	struct m5_publish msg = { .topic_name = (uint8_t *)TOPIC_NAME,
				  .topic_name_len = strlen(TOPIC_NAME),
				  .payload = (uint8_t *)PAYLOAD,
				  .payload_len = strlen(PAYLOAD),
				  .qos = qos };
	static uint16_t packet_id = 1;
	int rc;

	if (qos != M5_QoS0) {
		msg.packet_id = packet_id;
	}

	printf("Sending: PUBLISH, QoS: %d", qos);
	if (qos != M5_QoS0) {
		printf(", Packet Id: %d", msg.packet_id);
	}
	printf("\n");

	rc = pack_msg_write(socket_fd, M5_PKT_PUBLISH, &msg);
	if (rc != 0) {
		DBG("pack_msg_write");
		goto lb_error;
	}

	if (qos == M5_QoS0) {
		goto lb_exit;
	}

	rc = read_pub_response(socket_fd, packet_id, qos);
	if (rc != 0) {
		DBG("read_pub_response");
		goto lb_error;
	}

	packet_id += 1;

lb_exit:
	return 0;

lb_error:
	return -1;
}

static int publisher(void)
{
	uint8_t qos[] = { M5_QoS0, M5_QoS1, M5_QoS2 };
	int socket_fd;
	int i = 0;
	int rc;

	rc = publisher_connect(&socket_fd);
	if (rc != 0) {
		DBG("publisher_connect");
		goto lb_exit;
	}

	while (loop_forever) {
		rc = publish_msg(socket_fd, qos[i]);
		if (rc != 0) {
			DBG("publish_msg");
			goto lb_close;
		}
		sleep(1);

		i = (i + 1) % sizeof(qos);
	}

	rc = 0;

lb_close:
	tcp_disconnect(socket_fd);

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
	signal(SIGPIPE, signal_handler);
	signal(SIGTERM, signal_handler);
	signal(SIGINT, signal_handler);

	return publisher();
}
