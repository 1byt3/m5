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

static int echo(int client_fd)
{
	uint8_t rcodes[MAX_ARRAY_ELEMENTS];
	uint8_t out_data[MAX_BUF_SIZE];
	uint8_t in_data[MAX_BUF_SIZE];
	struct app_buf out = { .data = out_data, .size = sizeof(out_data) };
	struct app_buf in = { .data = in_data, .size = sizeof(in_data) };

	struct m5_pub_response msg_pub_response = { 0 };
	struct m5_subscribe msg_subscribe = { 0 };
	struct m5_connect msg_connect = { 0 };
	struct m5_connack msg_connack = { 0 };
	struct m5_publish msg_publish = { 0 };
	struct m5_suback msg_suback = { 0 };
	struct m5_prop prop = { 0 };

	struct m5_rc msg_rc = { 0 };
	uint8_t pkt_type;
	int rc;
	int i;

	rc = tcp_read(client_fd, &in);
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
		rc = m5_unpack_connect(NULL, &in, &msg_connect, &prop);
		break;
	case M5_PKT_CONNACK:
		rc = m5_unpack_connack(NULL, &in, &msg_connack, &prop);
		break;
	case M5_PKT_PUBLISH:
		rc = m5_unpack_publish(NULL, &in, &msg_publish, &prop);
		break;
	case M5_PKT_PUBACK:
		rc = m5_unpack_puback(NULL, &in, &msg_pub_response, &prop);
		break;
	case M5_PKT_PUBREC:
		rc = m5_unpack_pubrec(NULL, &in, &msg_pub_response, &prop);
		break;
	case M5_PKT_PUBREL:
		rc = m5_unpack_pubrel(NULL, &in, &msg_pub_response, &prop);
		break;
	case M5_PKT_PUBCOMP:
		rc = m5_unpack_pubcomp(NULL, &in, &msg_pub_response, &prop);
		break;
	case M5_PKT_SUBSCRIBE:
		rc = m5_unpack_subscribe(NULL, &in, &msg_subscribe, &prop);
		break;
	case M5_PKT_SUBACK:
		rc = m5_unpack_suback(NULL, &in, &msg_suback, &prop);
		break;
	case M5_PKT_UNSUBSCRIBE:
		rc = m5_unpack_unsubscribe(NULL, &in, &msg_subscribe);
		break;
	case M5_PKT_UNSUBACK:
		rc = m5_unpack_unsuback(NULL, &in, &msg_suback, &prop);
		break;
	case M5_PKT_PINGREQ:
		rc = m5_unpack_pingreq(NULL, &in);
		break;
	case M5_PKT_PINGRESP:
		rc = m5_unpack_pingresp(NULL, &in);
		break;
	case M5_PKT_DISCONNECT:
		rc = m5_unpack_disconnect(NULL, &in, &msg_rc, &prop);
		break;
	case M5_PKT_AUTH:
		rc = m5_unpack_auth(NULL, &in, &msg_rc, &prop);
		break;
	}

	printf("Received: %s\n", pkt_names[pkt_type]);

	if (rc != 0) {
		DBG("unpack");
		goto lb_exit;
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
		rc = m5_pack_connack(NULL, &out, &msg_connack, NULL);
		break;
	case M5_PKT_PUBLISH:
		msg_pub_response.packet_id = msg_publish.packet_id;
		msg_pub_response.reason_code = M5_RC_SUCCESS;
		switch ((enum m5_qos)msg_publish.qos) {
		case M5_QoS0:
			break;
		case M5_QoS1:
			rc = m5_pack_puback(NULL, &out,
					    &msg_pub_response, NULL);
			break;
		case M5_QoS2:
			rc = m5_pack_pubrec(NULL, &out,
					    &msg_pub_response, NULL);
			break;
		}
		break;
	case M5_PKT_PUBREC:
		rc = m5_pack_pubrel(NULL, &out,
				    &msg_pub_response, NULL);
		break;
	case M5_PKT_PUBREL:
		rc = m5_pack_pubcomp(NULL, &out,
				     &msg_pub_response, NULL);
		break;
	case M5_PKT_SUBSCRIBE:
	case M5_PKT_UNSUBSCRIBE:
		if (msg_subscribe.items > MAX_ARRAY_ELEMENTS) {
			DBG("subscribe items > MAX_ARRAY_ELEMENTS");
			rc = -1;
			goto lb_exit;
		}
		for (i = 0; i < msg_subscribe.items; i++) {
			uint8_t qos = msg_subscribe.topics[i].options & 0x03;

			msg_suback.rc[i] = qos;
		}
		msg_suback.rc_size = msg_subscribe.items;
		msg_suback.rc_items = msg_subscribe.items;
		msg_suback.rc = rcodes;
		if (pkt_type == M5_PKT_SUBSCRIBE) {
			rc = m5_pack_suback(NULL, &out, &msg_suback, NULL);
		} else {
			rc = m5_pack_unsuback(NULL, &out, &msg_suback, NULL);
		}
		break;
	case M5_PKT_PINGREQ:
		rc = m5_pack_pingresp(NULL, &out);
		break;
	case M5_PKT_AUTH:
		rc = m5_pack_auth(NULL, &out, 0x00, NULL);
		break;
	}

	if (rc != 0) {
		DBG("pack response");
		goto lb_exit;
	}

	if (out.len > 0) {
		rc = tcp_write(client_fd, &out);
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
			rc = echo(client_fd);
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

