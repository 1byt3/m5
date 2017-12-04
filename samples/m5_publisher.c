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

#define PEER_ADDR	{ 127, 0, 0, 1 }
#define PEER_PORT	1863

#define CLIENT_ID	"m5_publisher"
#define TOPIC_NAME	"greetings"
#define PAYLOAD		"Hello, World!"

static int loop_forever = 1;

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
	uint8_t peer_addr[] = PEER_ADDR;
	int socket_fd;
	int i = 0;
	int rc;

	rc = client_connect(&socket_fd, CLIENT_ID, peer_addr, PEER_PORT);
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
	set_tcp_timeout(5); /* seconds */

	signal(SIGPIPE, signal_handler);
	signal(SIGTERM, signal_handler);
	signal(SIGINT, signal_handler);

	return publisher();
}
