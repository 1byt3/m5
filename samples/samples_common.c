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
	int option = 1;
	int rc = -1;

	*server_fd = socket(AF_INET, SOCK_STREAM, 0);
	if (*server_fd < 0) {
		DBG("socket");
		goto lb_exit;
	}

	rc = setsockopt(*server_fd, SOL_SOCKET, SO_REUSEADDR,
			&option, sizeof(option));
	if (rc != 0) {
		DBG("setsockopt SO_REUSEADDR");
		goto lb_close;
	}

	rc = setsockopt(*server_fd, SOL_SOCKET, SO_REUSEPORT,
			&option, sizeof(option));
	if (rc != 0) {
		DBG("setsockopt SO_REUSEPORT");
		goto lb_close;
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
		break;
	case M5_PKT_CONNACK:
		rc = m5_pack_connack(NULL, &buf,
				     (struct m5_connack *)msg, NULL);
		break;
	case M5_PKT_SUBSCRIBE:
		rc = m5_pack_subscribe(NULL, &buf,
				       (struct m5_subscribe *)msg, NULL);
		break;
	case M5_PKT_SUBACK:
		rc = m5_pack_suback(NULL, &buf,
				    (struct m5_suback *)msg, NULL);
		break;
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

#define PACK_UNPACK(pre, packet, m5_type, ...)				\
static int pre ## _ ## packet(struct m5_ctx *ctx, struct app_buf *buf,	\
			      void *_msg, struct m5_prop *prop)		\
{									\
	m5_type *msg;							\
									\
	(void)prop;							\
	(void)_msg;							\
	(void)msg;							\
	msg = (m5_type *)_msg;						\
	return m5_ ## pre ## _ ## packet(ctx, buf, ## __VA_ARGS__);	\
}

PACK_UNPACK(pack, connect, struct m5_connect, msg, prop)
PACK_UNPACK(pack, connack, struct m5_connack, msg, prop)
PACK_UNPACK(pack, publish, struct m5_publish, msg, prop)
PACK_UNPACK(pack, puback, struct m5_pub_response, msg, prop)
PACK_UNPACK(pack, pubrec, struct m5_pub_response, msg, prop)
PACK_UNPACK(pack, pubrel, struct m5_pub_response, msg, prop)
PACK_UNPACK(pack, pubcomp, struct m5_pub_response, msg, prop)
PACK_UNPACK(pack, subscribe, struct m5_subscribe, msg, prop)
PACK_UNPACK(pack, suback, struct m5_suback, msg, prop)
PACK_UNPACK(pack, unsubscribe, struct m5_subscribe, msg)
PACK_UNPACK(pack, unsuback, struct m5_suback, msg, prop)
PACK_UNPACK(pack, pingreq, void)
PACK_UNPACK(pack, pingresp, void)
PACK_UNPACK(pack, disconnect, struct m5_rc, msg, prop)
PACK_UNPACK(pack, auth, struct m5_rc, msg, prop)

PACK_UNPACK(unpack, connect, struct m5_connect, msg, prop)
PACK_UNPACK(unpack, connack, struct m5_connack, msg, prop)
PACK_UNPACK(unpack, publish, struct m5_publish, msg, prop)
PACK_UNPACK(unpack, puback, struct m5_pub_response, msg, prop)
PACK_UNPACK(unpack, pubrec, struct m5_pub_response, msg, prop)
PACK_UNPACK(unpack, pubrel, struct m5_pub_response, msg, prop)
PACK_UNPACK(unpack, pubcomp, struct m5_pub_response, msg, prop)
PACK_UNPACK(unpack, subscribe, struct m5_subscribe, msg, prop)
PACK_UNPACK(unpack, suback, struct m5_suback, msg, prop)
PACK_UNPACK(unpack, unsubscribe, struct m5_subscribe, msg)
PACK_UNPACK(unpack, unsuback, struct m5_suback, msg, prop)
PACK_UNPACK(unpack, pingreq, void)
PACK_UNPACK(unpack, pingresp, void)
PACK_UNPACK(unpack, disconnect, struct m5_rc, msg, prop)
PACK_UNPACK(unpack, auth, struct m5_rc, msg, prop)

typedef int (*fptr_pack_unpack)(struct m5_ctx *, struct app_buf *,
				void *, struct m5_prop *);

static fptr_pack_unpack fptr_pack[] = {
	NULL,
	pack_connect,
	pack_connack,
	pack_publish,
	pack_puback,
	pack_pubrec,
	pack_pubrel,
	pack_pubcomp,
	pack_subscribe,
	pack_suback,
	pack_unsubscribe,
	pack_unsuback,
	pack_pingreq,
	pack_pingresp,
	pack_disconnect,
	pack_auth };

static fptr_pack_unpack fptr_unpack[] = {
	NULL,
	unpack_connect,
	unpack_connack,
	unpack_publish,
	unpack_puback,
	unpack_pubrec,
	unpack_pubrel,
	unpack_pubcomp,
	unpack_subscribe,
	unpack_suback,
	unpack_unsubscribe,
	unpack_unsuback,
	unpack_pingreq,
	unpack_pingresp,
	unpack_disconnect,
	unpack_auth };

static int prep_resp_publish(void *dst, void *src)
{
	struct m5_pub_response *pub_response = (struct m5_pub_response *)dst;
	struct m5_publish *publish = (struct m5_publish *)src;

	if (publish->qos == M5_QoS0 ||
	    (publish->qos != M5_QoS1 && publish->qos != M5_QoS2)) {
		return -1;
	}

	pub_response->packet_id = publish->packet_id;
	pub_response->reason_code = M5_RC_SUCCESS;

	return 0;
}

static int prep_resp_subscribe(void *dst, void *src)
{
	struct m5_subscribe *subscribe = (struct m5_subscribe *)src;
	struct m5_suback *suback = (struct m5_suback *)dst;
	uint8_t i;

	if (subscribe->items > suback->rc_size) {
		return -1;
	}

	for (i = 0; i < subscribe->items; i++) {
		uint8_t qos = subscribe->topics[i].options & 0x03;

		suback->rc[i] = qos;
	}

	suback->packet_id = subscribe->packet_id;
	suback->rc_items = subscribe->items;

	return 0;
}

typedef int (*fptr_prep_resp)(void *, void *);

static fptr_prep_resp prep_resp[] = {
	NULL,
	NULL,			/* CONNECT, use default values */
	NULL,			/* CONNACK, no response */
	prep_resp_publish,	/* PUBLISH */
	NULL,			/* PUBACK, no response */
	NULL,			/* PUBREC, will use the same msg */
	NULL,			/* PUBREL, will use the same msg */
	NULL,			/* PUBCOMP, no response */
	prep_resp_subscribe,	/* SUBSCRIBE */
	NULL,			/* SUBACK, no response */
	prep_resp_subscribe,	/* UNSUBSCRIBE */
	NULL,			/* UNSUBACK, no response */
	NULL,			/* PINGREQ, no extra processing required */
	NULL,			/* PINGRESP, no extra processing required */
	NULL,			/* DISCONNECT, no response */
	NULL };			/* AUTH, send the same message back */

static int pkt_resp[] = {
	M5_PKT_RESERVED,
	M5_PKT_CONNACK,		/* CONNECT */
	M5_PKT_RESERVED,	/* CONNACK */
	M5_PKT_RESERVED,	/* PUBLISH, depends on QoS value */
	M5_PKT_RESERVED,	/* PUBACK */
	M5_PKT_PUBREL,		/* PUBREC */
	M5_PKT_PUBCOMP,		/* PUBREL */
	M5_PKT_RESERVED,	/* PUBCOMP */
	M5_PKT_SUBACK,		/* SUBSCRIBE */
	M5_PKT_RESERVED,	/* SUBACK */
	M5_PKT_UNSUBACK,	/* UNSUBSCRIBE */
	M5_PKT_RESERVED,	/* UNSUBACK */
	M5_PKT_PINGRESP,	/* PINGREQ */
	M5_PKT_RESERVED,	/* PINGRESP */
	M5_PKT_AUTH,		/* AUTH */
	M5_PKT_RESERVED };	/* DISCONNECT */

int unpack_msg_reply(int fd,
		     int validate_packet(enum m5_pkt_type pkt_type,
					 void *msg,
					 void *data),
		     void *user_data)
{
	struct m5_pub_response msg_pub_response = { 0 };
	struct m5_subscribe msg_subscribe = { 0 };
	struct m5_connect msg_connect = { 0 };
	struct m5_connack msg_connack = { 0 };
	struct m5_publish msg_publish = { 0 };
	struct m5_suback msg_suback = { 0 };
	struct m5_rc msg_rc = { 0 };
	struct m5_prop prop = { 0 };
	void *msgs[] = {
		NULL,
		&msg_connect,
		&msg_connack,
		&msg_publish,
		&msg_pub_response,
		&msg_pub_response,
		&msg_pub_response,
		&msg_pub_response,
		&msg_subscribe,
		&msg_suback,
		&msg_subscribe,
		&msg_suback,
		NULL,
		NULL,
		&msg_rc,
		&msg_rc };
	struct m5_topic topics[MAX_ARRAY_ELEMENTS];
	uint8_t rcodes[MAX_ARRAY_ELEMENTS];
	uint8_t out_data[MAX_BUF_SIZE];
	uint8_t in_data[MAX_BUF_SIZE];
	struct app_buf out;
	struct app_buf in;
	uint8_t pkt_type;
	int rc;

	in.data = in_data;
	in.size = sizeof(in_data);
	out.data = out_data;
	out.size = sizeof(out_data);
	msg_subscribe.topics = topics;
	msg_subscribe.size = MAX_ARRAY_ELEMENTS;
	msg_suback.rc = rcodes;
	msg_suback.rc_size = MAX_ARRAY_ELEMENTS;

	rc = tcp_read(fd, &in);
	if (rc != 0) {
		DBG("tcp_read");
		return -1;
	}

lb_parse_another_packet:
	pkt_type = (*buf_current(&in) >> 4);

	if (pkt_type <= M5_PKT_RESERVED || pkt_type >= M5_PKT_RESERVED_UB) {
		DBG("invalid control packet");
		return -1;
	}

	printf("Received: %s\n", pkt_names[pkt_type]);

	rc = fptr_unpack[pkt_type](NULL, &in, msgs[pkt_type], &prop);
	if (rc != 0) {
		DBG("unpack");
		return -1;
	}

	if (validate_packet != NULL) {
		rc = validate_packet(pkt_type, msgs[pkt_type], user_data);
		if (rc != 0) {
			DBG("validate_packet");
			return -1;
		}
	}

	if (pkt_type == M5_PKT_PUBLISH) {
		int state;

		state  = publisher_next_state(M5_PKT_PUBLISH, msg_publish.qos);
		if (state == -1) {
			return -1;
		}
		pkt_resp[M5_PKT_PUBLISH] = state;
	}

	if (pkt_resp[pkt_type] == M5_PKT_RESERVED) {
		return 0;
	}

	printf("Sending: %s\n", pkt_names[pkt_resp[pkt_type]]);

	if (prep_resp[pkt_type] != NULL) {
		rc = prep_resp[pkt_type](msgs[pkt_resp[pkt_type]],
					 msgs[pkt_type]);
		if (rc != 0) {
			DBG("prep_resp");
			return -1;
		}
	}

	buf_reset(&out);
	rc = fptr_pack[pkt_resp[pkt_type]](NULL, &out,
					   msgs[pkt_resp[pkt_type]], NULL);
	if (rc != 0) {
		DBG("pack response");
		return -1;
	}

	rc = tcp_write(fd, &out);
	if (rc != 0) {
		DBG("tcp_write");
		return -1;
	}

	if (buf_bytes_to_read(&in) > 0) {
		/* more data to parse */
		goto lb_parse_another_packet;
	}

	return 0;
}

int publisher_next_state(int current_state, enum m5_qos qos)
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

struct user_data {
	uint8_t current_state;
	enum m5_qos qos;
	int packet_id;
};

static int validate_pub_packet(enum m5_pkt_type pkt_type,
			       void *msg, void *user)
{
	struct m5_pub_response *resp = (struct m5_pub_response *)msg;
	struct user_data *user_data = (struct user_data *)user;
	uint8_t next;

	if (pkt_type == M5_PKT_PINGREQ) {
		return 0;
	}

	/* current_state is the state before pkt_type */
	next = publisher_next_state(user_data->current_state, user_data->qos);
	if (next == M5_PKT_RESERVED) {
		return 0;
	}

	/* next must match the received packet */
	if (next != pkt_type) {
		DBG("unexpected control packet received");
		return -1;
	}

	if (resp->packet_id != user_data->packet_id ||
	    resp->reason_code != 0) {
		DBG("invalid packet id or reason code in pub response");
		return -1;
	}

	/* pkt_type is the previous state, so we compute the next state here */
	next = publisher_next_state(pkt_type, user_data->qos);
	user_data->current_state = next;

	return 0;
}

int publish_message(int fd, struct m5_publish *msg, int *loop_forever)
{
	struct user_data user_data;
	int rc;

	/* keep the type and qos for future PUB messages */
	user_data.current_state = M5_PKT_PUBLISH;
	user_data.packet_id = msg->packet_id;
	user_data.qos = msg->qos;

	rc = pack_msg_write(fd, M5_PKT_PUBLISH, msg);
	if (rc != 0) {
		DBG("pack_msg_write");
		return -1;
	}

	if (msg->qos == M5_QoS0) {
		return 0;
	}

	/* loop until the PUBLISH handshake is fnished */
	while (*loop_forever) {
		rc = unpack_msg_reply(fd, validate_pub_packet, &user_data);
		if (rc != 0) {
			DBG("unpack_msg_reply");
			return -1;
		}

		if (user_data.current_state == M5_PKT_RESERVED) {
			break;
		}
	}

	return 0;
}

