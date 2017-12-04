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
#include "m5.h"

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
#define CLIENT_ID	"m5_subscriber"

static int loop_forever;

static struct m5_topic topic_filters[] = {
	{ .name = (uint8_t *)"srv/one", .len = 7, .options = M5_QoS1 },
	{ .name = (uint8_t *)"sensors", .len = 7, .options = M5_QoS2 },
	{ .name = (uint8_t *)"doors",   .len = 5, .options = M5_QoS0 },
	{ .name = NULL } };

/* This routine does not consider wildcards in topic filters, it just
 * compares the topic name from a PUBLISH packet to all the topic filters
 * found at the topic_filters array.
 */
static int validate_topic(uint8_t *topic_name, uint16_t topic_name_len,
			  struct m5_topic topic_filters[], uint8_t items)
{
	uint8_t i;

	for (i = 0; i < items; i++) {
		const char *topic_filter = (const char *)topic_filters[i].name;
		int rc;

		if (strlen(topic_filter) != topic_name_len) {
			continue;
		}

		rc = memcmp(topic_filter, (char *)topic_name, topic_name_len);
		if (rc == 0) {
			return 0;
		}
	}

	return -1;
}

static uint16_t pkt_ids[2 * MAX_ARRAY_ELEMENTS] = { 0 };
static int max_pkt_ids = MAX_ARRAY_ELEMENTS;

static int find_pkt_id(uint16_t pkt_id)
{
	int i;

	for (i = 0; i < max_pkt_ids; i++) {
		if (pkt_ids[2 * i] == pkt_id) {
			return i;
		}
	}

	return -1;
}

static int find_pkt_id_qos(uint16_t pkt_id, enum m5_qos qos)
{
	int idx;

	idx = find_pkt_id(pkt_id);
	if (idx < 0) {
		return -1;
	}

	if (pkt_ids[2 * idx + 1] == qos) {
		return idx;
	}

	return -1;
}

static int add_pkt_id(uint16_t pkt_id, enum m5_qos qos)
{
	int i;

	if (pkt_id == 0) {
		return -1;
	}
	switch (qos) {
	default:
	case M5_QoS0:
		return -1;
	case M5_QoS1:
	case M5_QoS2:
		break;
	}

	i = find_pkt_id(pkt_id);
	if (i >= 0) {
		return -1;
	}

	for (i = 0; i < max_pkt_ids; i++) {
		if (pkt_ids[2 * i] == 0) {
			pkt_ids[2 * i + 0] = pkt_id;
			pkt_ids[2 * i + 1] = qos;

			return 0;
		}
	}

	return -1;
}

static void delete_idx(int idx)
{
	pkt_ids[2 * idx + 0] = 0;
	pkt_ids[2 * idx + 1] = 0;
}

static int validate_packet(enum m5_pkt_type pkt_type, void *msg, void *user)
{
	struct m5_publish *msg_publish;
	struct m5_pub_response *resp;
	uint8_t items = 0;
	int rc = -1;
	int idx;

	(void)user;

	while (topic_filters[items].name != NULL) {
		items += 1;
	}

	switch (pkt_type) {
	default:
		DBG("invalid control packet for subscriber application");
		goto lb_error;
	case M5_PKT_PUBLISH:
		msg_publish = (struct m5_publish *)msg;

		rc = validate_topic(msg_publish->topic_name,
				    msg_publish->topic_name_len,
				    topic_filters, items);
		if (rc != 0) {
			DBG("invalid topic");
			goto lb_error;
		}

		if (msg_publish->qos == M5_QoS2) {
			rc = add_pkt_id(msg_publish->packet_id,
					msg_publish->qos);
			if (rc != 0) {
				DBG("unable to accept PUBLISH msg");
				goto lb_error;
			}
		}
		break;
	case M5_PKT_PUBREL:
		resp = (struct m5_pub_response *)msg;

		idx = find_pkt_id_qos(resp->packet_id, M5_QoS2);
		if (idx < 0) {
			DBG("invalid packet id");
			goto lb_error;
		}

		delete_idx(idx);
		break;
	case M5_PKT_PINGREQ:
	case M5_PKT_PINGRESP:
		break;
	}

	return 0;

lb_error:
	return -1;
}

static int client_subscribe(int fd)
{
	uint8_t data[MAX_BUF_SIZE];
	struct app_buf buf = { .data = data,
			       .size = sizeof(data) };
	uint8_t rcodes[MAX_ARRAY_ELEMENTS];
	struct m5_suback msg_suback = { .rc = rcodes,
					.rc_size = MAX_ARRAY_ELEMENTS };
	struct m5_prop prop = { 0 };
	struct m5_subscribe msg;
	uint8_t items = 0;
	int rc;

	msg.topics = topic_filters;
	while (topic_filters[items].name != NULL) {
		items += 1;
	}

	msg.items = items;
	msg.size = items;
	msg.packet_id = 0x01;

	rc = pack_msg_write(fd, M5_PKT_SUBSCRIBE, &msg);
	if (rc != 0) {
		DBG("pack_msg_write SUBSCRIBE");
		return -1;
	}

	rc = tcp_read(fd, &buf);
	if (rc != 0) {
		DBG("tcp_read");
		return -1;
	}

	rc = m5_unpack_suback(NULL, &buf, &msg_suback, &prop);
	if (rc != 0) {
		DBG("m5_unpack_suback");
		return -1;
	}

	return 0;
}

static int subscriber(void)
{
	uint8_t peer_addr[] = PEER_ADDR;
	int socket_fd;
	int rc;

	rc = client_connect(&socket_fd, CLIENT_ID, peer_addr, PEER_PORT);
	if (rc != 0) {
		DBG("client_connect");
		goto lb_exit;
	}

	rc = client_subscribe(socket_fd);
	if (rc != 0) {
		DBG("client_subscribe");
		goto lb_exit;
	}

	while (loop_forever) {
		rc = unpack_msg_reply(socket_fd, validate_packet, NULL);
		if (rc != 0) {
			DBG("unpack_msg_reply");
			goto lb_close;
		}
	}

	rc = 0;

lb_close:
	printf("Connection closed\n");
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

	loop_forever = 1;

	signal(SIGPIPE, signal_handler);
	signal(SIGTERM, signal_handler);
	signal(SIGINT, signal_handler);

	return subscriber();
}

