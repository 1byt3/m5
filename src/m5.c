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

#include <stdlib.h>
#include <string.h>
#include <errno.h>

#define APPBUF_FREE_READ_SPACE(buf) (buf->len - buf->offset)
#define APPBUF_FREE_WRITE_SPACE(buf) (buf->size - buf->len)
#define APPBUF_DATAPTR_CURRENT(buf) (buf->data + buf->offset)

#define M5_BINARY_LEN_SIZE	2u
#define M5_STR_LEN_SIZE		M5_BINARY_LEN_SIZE
#define M5_INT_LEN_SIZE		2
#define M5_PROTO_STR		"MQTT"
#define M5_PROTO_NAME_LEN	6u
#define M5_PROTO_VERSION5	0x05

#define M5_CLIENTID_MIN_LEN	1
#define M5_CLIENTID_MAX_LEN	23

#define M5_PACKET_TYPE_WSIZE	1

enum m5_prop_val {
	/* empty */
	PAYLOAD_FORMAT_INDICATOR = 0x01,
	PUBLICATION_EXPIRY_INTERVAL,
	CONTENT_TYPE,
	/* empty */
	/* empty */
	/* empty */
	/* empty */
	RESPONSE_TOPIC = 0x08,
	CORRELATION_DATA,
	/* empty */
	SUBSCRIPTION_IDENTIFIER = 0x0B,
	/* empty */
	/* empty */
	/* empty */
	/* empty */
	/* empty */
	SESSION_EXPIRY_INTERVAL = 0x11,
	ASSIGNED_CLIENT_IDENTIFIER,
	SERVER_KEEP_ALIVE,
	/* empty */
	AUTH_METHOD = 0x15,
	AUTH_DATA,
	REQUEST_PROBLEM_INFORMATION,
	WILL_DELAY_INTERVAL,
	REQUEST_RESPONSE_INFORMATION,
	RESPONSE_INFORMATION,
	/* empty */
	SERVER_REFERENCE  = 0x1C,
	/* empty */
	/* empty */
	REASON_STR = 0x1F,
	/* empty */
	RECEIVE_MAXIMUM = 0x21,
	TOPIC_ALIAS_MAXIMUM,
	TOPIC_ALIAS,
	MAXIMUM_QOS,
	RETAIN_AVAILABLE,
	USER_PROPERTY,
	MAXIMUM_PACKET_SIZE,
	WILDCARD_SUBSCRIPTION_AVAILABLE,
	SUBSCRIPTION_IDENTIFIER_AVAILABLE,
	SHARED_SUBSCRIPTION_AVAILABLE,
	M5_PROP_LEN
};

enum m5_prop_remap {
	/* u8 properties */
	REMAP_PAYLOAD_FORMAT_INDICATOR = 1,
	REMAP_REQUEST_PROBLEM_INFORMATION,
	REMAP_REQUEST_RESPONSE_INFORMATION,
	REMAP_MAXIMUM_QOS,
	REMAP_RETAIN_AVAILABLE,
	REMAP_WILDCARD_SUBSCRIPTION_AVAILABLE,
	REMAP_SUBSCRIPTION_IDENTIFIER_AVAILABLE,
	REMAP_SHARED_SUBSCRIPTION_AVAILABLE,

	/* u16 properties */
	REMAP_SERVER_KEEP_ALIVE,
	REMAP_RECEIVE_MAXIMUM,
	REMAP_TOPIC_ALIAS_MAXIMUM,
	REMAP_TOPIC_ALIAS,

	/* u32 properties */
	REMAP_PUBLICATION_EXPIRY_INTERVAL,
	REMAP_SESSION_EXPIRY_INTERVAL,
	REMAP_WILL_DELAY_INTERVAL,
	REMAP_MAXIMUM_PACKET_SIZE,

	/* binary or string based properties */
	REMAP_CONTENT_TYPE,
	REMAP_RESPONSE_TOPIC,
	REMAP_CORRELATION_DATA,
	REMAP_ASSIGNED_CLIENT_IDENTIFIER,
	REMAP_AUTH_METHOD,
	REMAP_AUTH_DATA,
	REMAP_RESPONSE_INFORMATION,
	REMAP_SERVER_REFERENCE,
	REMAP_REASON_STR,

	/* var length */
	REMAP_SUBSCRIPTION_IDENTIFIER,

	/* key value pair */
	REMAP_USER_PROPERTY,

	M5_REMAP_PROP_LEN
};

static const uint8_t prop_2_remap[] = {
	0,
	REMAP_PAYLOAD_FORMAT_INDICATOR,
	REMAP_PUBLICATION_EXPIRY_INTERVAL,
	REMAP_CONTENT_TYPE,
	0,
	0,
	0,
	0,
	REMAP_RESPONSE_TOPIC,
	REMAP_CORRELATION_DATA,
	0,
	REMAP_SUBSCRIPTION_IDENTIFIER,
	0,
	0,
	0,
	0,
	0,
	REMAP_SESSION_EXPIRY_INTERVAL,
	REMAP_ASSIGNED_CLIENT_IDENTIFIER,
	REMAP_SERVER_KEEP_ALIVE,
	0,
	REMAP_AUTH_METHOD,
	REMAP_AUTH_DATA,
	REMAP_REQUEST_PROBLEM_INFORMATION,
	REMAP_WILL_DELAY_INTERVAL,
	REMAP_REQUEST_RESPONSE_INFORMATION,
	REMAP_RESPONSE_INFORMATION,
	0,
	REMAP_SERVER_REFERENCE,
	0,
	0,
	REMAP_REASON_STR,
	0,
	REMAP_RECEIVE_MAXIMUM,
	REMAP_TOPIC_ALIAS_MAXIMUM,
	REMAP_TOPIC_ALIAS,
	REMAP_MAXIMUM_QOS,
	REMAP_RETAIN_AVAILABLE,
	REMAP_USER_PROPERTY,
	REMAP_MAXIMUM_PACKET_SIZE,
	REMAP_WILDCARD_SUBSCRIPTION_AVAILABLE,
	REMAP_SUBSCRIPTION_IDENTIFIER_AVAILABLE,
	REMAP_SHARED_SUBSCRIPTION_AVAILABLE
};

static int m5_rlen_wsize(uint32_t val, uint32_t *wsize)
{
	if (val > 268435455) {
		return -EINVAL;
	}

	if (val <= 127) {
		*wsize = 1;
	} else if (val <= 16383) {
		*wsize = 2;
	} else if (val <= 2097151) {
		*wsize = 3;
	} else if (val <= 268435455) {
		*wsize = 4;
	}

	return EXIT_SUCCESS;
}

static int m5_encode_int(struct app_buf *buf, uint32_t value)
{
	do {
		uint8_t encoded;

		if (buf->len >= buf->size) {
			return -ENOMEM;
		}

		encoded = value % 128;
		value = value / 128;
		if (value > 0) {
			encoded = encoded | 128;
		}

		buf->data[buf->len] = encoded;
		buf->len += 1;
	} while (value > 0);

	return EXIT_SUCCESS;
}

static int m5_decode_int(struct app_buf *buf, uint32_t *value,
			 uint32_t *val_wsize)
{
	uint32_t multiplier = 1;
	uint8_t encoded;
	int i = 0;

	*value = 0;
	do {
		if (APPBUF_FREE_READ_SPACE(buf) < 1) {
			return -ENOMEM;
		}

		if (multiplier > 128 * 128 * 128) {
			return -EINVAL;
		}

		encoded = buf->data[buf->offset + i++];

		*value += (encoded & 127) * multiplier;
		multiplier *= 128;
	} while ((encoded & 128) != 0);


	buf->offset += i;
	*val_wsize = i;

	return EXIT_SUCCESS;
}

static void m5_add_u8(struct app_buf *buf, uint8_t val)
{
	buf->data[buf->len] = val;
	buf->len += 1;
}

static void m5_add_u16(struct app_buf *buf, uint16_t val)
{
	uint16_t net_order = htobe16(val);
	uint8_t *p = (uint8_t *)&net_order;

	buf->data[buf->len + 0] = p[0];
	buf->data[buf->len + 1] = p[1];
	buf->len += 2;
}

static void m5_add_raw_binary(struct app_buf *buf,
			      uint8_t *src, uint16_t src_len)
{
	memcpy(buf->data + buf->len, src, src_len);
	buf->len += src_len;
}

static void m5_add_binary(struct app_buf *buf, uint8_t *src, uint16_t src_len)
{
	m5_add_u16(buf, src_len);
	m5_add_raw_binary(buf, src, src_len);
}

static void m5_str_add(struct app_buf *buf, const char *str)
{
	m5_add_binary(buf, (uint8_t *)str, strlen(str));
}

/* Recovers a 2 byte integer in data. Integers are stored in Network order */
static uint16_t m5_u16(uint8_t *data)
{
	return (data[0] << 8) + data[1];
}

static int m5_connect_payload_wsize(struct m5_connect *msg,
				    uint32_t *wire_size)
{
	if (msg->client_id_len < M5_CLIENTID_MIN_LEN ||
	    msg->client_id_len > M5_CLIENTID_MAX_LEN) {
		return -EINVAL;
	}

	*wire_size = M5_STR_LEN_SIZE  + msg->client_id_len;

	if (msg->will_msg_len > 0 && msg->will_topic_len > 0) {
		*wire_size += M5_STR_LEN_SIZE  + msg->will_topic_len +
			      M5_BINARY_LEN_SIZE + msg->will_msg_len;
	} else if (msg->will_msg_len  + msg->will_topic_len != 0) {
		return -EINVAL;
	}

	if (msg->user_name_len > 0) {
		*wire_size += M5_STR_LEN_SIZE + msg->user_name_len;
	}

	if (msg->password_len > 0) {
		*wire_size += M5_BINARY_LEN_SIZE + msg->password_len;
	}

	return EXIT_SUCCESS;
}

static void m5_connect_compute_flags(struct m5_connect *msg, uint8_t *flags)
{
	*flags = (msg->clean_start << 0x01) +
		 (msg->will_msg_len > 0 ? (0x01 << 2) : 0) +
		 ((msg->will_qos & 0x03) << 3) +
		 (msg->will_retain == 1 ? (1 << 5) : 0) +
		 (msg->password_len > 0 ? (0x01 << 6) : 0) +
		 (msg->user_name_len > 0 ? (0x01 << 7) : 0);
}

static int m5_pack_connect_payload(struct app_buf *buf, struct m5_connect *msg)
{
	m5_add_binary(buf, msg->client_id, msg->client_id_len);

	if (msg->will_msg_len > 0) {
		m5_add_binary(buf, msg->will_topic, msg->will_topic_len);
		m5_add_binary(buf, msg->will_msg, msg->will_msg_len);
	}

	if (msg->user_name_len > 0) {
		m5_add_binary(buf, msg->user_name, msg->user_name_len);
	}

	if (msg->password_len > 0) {
		m5_add_binary(buf, msg->password, msg->password_len);
	}

	return EXIT_SUCCESS;
}

int m5_pack_connect(struct app_buf *buf, struct m5_connect *msg)
{
	uint32_t payload_wsize;
	uint32_t full_msg_size;
	uint32_t prop_wsize;
	uint32_t rlen_wsize;
	uint32_t rlen;
	uint8_t flags;
	int rc;

	if (buf == NULL || msg == NULL) {
		return -EINVAL;
	}

	/* xxx Assume that there are no properties... */
	prop_wsize = 0;

	rc = m5_connect_payload_wsize(msg, &payload_wsize);
	if (rc != EXIT_SUCCESS) {
		return rc;
	}

	rlen = M5_PROTO_NAME_LEN + 1 + 1 + 2 +
	       1 + prop_wsize + payload_wsize;

	rc = m5_rlen_wsize(rlen, &rlen_wsize);
	if (rc != EXIT_SUCCESS) {
		return rc;
	}

	full_msg_size = M5_PACKET_TYPE_WSIZE + rlen + rlen_wsize;
	if (APPBUF_FREE_WRITE_SPACE(buf) < full_msg_size) {
		return -ENOMEM;
	}

	m5_connect_compute_flags(msg, &flags);

	m5_add_u8(buf, M5_PKT_CONNECT << 4);
	m5_encode_int(buf, rlen);
	m5_str_add(buf, M5_PROTO_STR);
	m5_add_u8(buf, M5_PROTO_VERSION5);
	m5_add_u8(buf, flags);
	m5_add_u16(buf, msg->keep_alive);

	/* xxx Pack properties: 0 length */
	m5_encode_int(buf, prop_wsize);

	rc = m5_pack_connect_payload(buf, msg);

	return rc;
}
