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

#if defined(__FreeBSD__)
#include <sys/endian.h>
#else
#include <endian.h>
#endif

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

#define PROP_ID_BYTE_WSIZE	1

#define M5_PACKET_ID_WSIZE	2

#define M5_CONNECT_FLAGS_WSIZE	1

#ifndef ARG_UNUSED
#define ARG_UNUSED(arg)	((void)arg)
#endif

#define M5_2POW(n) (uint32_t)(((uint32_t)1) << n)

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

typedef void(*fcn_prop_u8)(struct m5_prop *, uint8_t);
typedef void(*fcn_prop_u16)(struct m5_prop *, uint16_t);
typedef void(*fcn_prop_u32)(struct m5_prop *, uint32_t);
typedef void(*fcn_prop_binary)(struct m5_prop *, uint8_t *, uint16_t);

struct m5_prop_conf {
	int (*wire_size)(struct m5_prop *, enum m5_prop_remap, uint32_t *);
	void (*prop2buf)(struct app_buf *, struct m5_prop *);
	int (*buf2prop)(struct app_buf *, struct m5_prop *);
	uint32_t valid_msgs;
};

size_t buf_bytes_to_read(struct app_buf *buf)
{
	return APPBUF_FREE_READ_SPACE(buf);
}

size_t buf_bytes_to_write(struct app_buf *buf)
{
	return APPBUF_FREE_WRITE_SPACE(buf);
}

uint8_t *buf_current(struct app_buf *buf)
{
	return APPBUF_DATAPTR_CURRENT(buf);
}

void buf_reset(struct app_buf *buf)
{
	buf->offset = 0;
	buf->len = 0;
}

static void m5_ctx_status(struct m5_ctx *ctx, enum m5_status status)
{
	if (ctx == NULL) {
		return;
	}

	ctx->status = status;
}

static int m5_rlen_wsize(uint32_t val, uint32_t *wsize)
{
	if (val > 268435455) {
		return M5_INVALID_ARGUMENT;
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

	return M5_SUCCESS;
}

static int m5_encode_int(struct app_buf *buf, uint32_t value)
{
	do {
		uint8_t encoded;

		if (buf->len >= buf->size) {
			return M5_NOT_ENOUGH_SPACE_IN_BUFFER;
		}

		encoded = value % 128;
		value = value / 128;
		if (value > 0) {
			encoded = encoded | 128;
		}

		buf->data[buf->len] = encoded;
		buf->len += 1;
	} while (value > 0);

	return M5_SUCCESS;
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
			return M5_NOT_ENOUGH_SPACE_IN_BUFFER;
		}

		if (multiplier > 128 * 128 * 128) {
			return M5_INVALID_ARGUMENT;
		}

		encoded = buf->data[buf->offset + i++];

		*value += (encoded & 127) * multiplier;
		multiplier *= 128;
	} while ((encoded & 128) != 0);


	buf->offset += i;
	*val_wsize = i;

	return M5_SUCCESS;
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

static void m5_add_u32(struct app_buf *buf, uint32_t val)
{
	uint32_t net_order = htobe32(val);
	uint8_t *p = (uint8_t *)&net_order;

	buf->data[buf->len + 0] = p[0];
	buf->data[buf->len + 1] = p[1];
	buf->data[buf->len + 2] = p[2];
	buf->data[buf->len + 3] = p[3];
	buf->len += 4;
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

static int m5_pack_raw_binary(struct app_buf *buf,
			      uint8_t *src, uint16_t src_len)
{
	if (src_len == 0 || APPBUF_FREE_WRITE_SPACE(buf) < src_len) {
		return M5_NOT_ENOUGH_SPACE_IN_BUFFER;
	}

	m5_add_raw_binary(buf, src, src_len);

	return M5_SUCCESS;
}

static void m5_str_add(struct app_buf *buf, const char *str)
{
	m5_add_binary(buf, (uint8_t *)str, strlen(str));
}

/* Recovers a 2 byte integer in Network order */
static uint16_t m5_u16(uint8_t *data)
{
	return (data[0] << 8) + data[1];
}

/* Recovers a 4 byte integer in Network order */
static uint32_t m5_u32(uint8_t *data)
{
	return (data[0] << 24) + (data[1] << 16) + (data[2] << 8) + data[3];
}

static int m5_unpack_u8(struct app_buf *buf, uint8_t *val)
{
	if (APPBUF_FREE_READ_SPACE(buf) < 1) {
		return M5_NOT_ENOUGH_SPACE_IN_BUFFER;
	}

	*val = buf->data[buf->offset];
	buf->offset += 1;

	return M5_SUCCESS;
}

static int m5_unpack_u16(struct app_buf *buf, uint16_t *val)
{
	if (APPBUF_FREE_READ_SPACE(buf) < 2) {
		return M5_NOT_ENOUGH_SPACE_IN_BUFFER;
	}

	*val = m5_u16(buf->data + buf->offset);
	buf->offset += 2;

	return M5_SUCCESS;
}

static int m5_unpack_binary(struct app_buf *buf, uint8_t **data, uint16_t *len)
{
	if (APPBUF_FREE_READ_SPACE(buf) < M5_BINARY_LEN_SIZE) {
		return M5_NOT_ENOUGH_SPACE_IN_BUFFER;
	}

	*len = m5_u16(buf->data + buf->offset);
	if (APPBUF_FREE_READ_SPACE(buf) < M5_BINARY_LEN_SIZE + *len) {
		return M5_NOT_ENOUGH_SPACE_IN_BUFFER;
	}

	*data = buf->data + buf->offset + M5_BINARY_LEN_SIZE;
	buf->offset += M5_BINARY_LEN_SIZE + *len;

	return M5_SUCCESS;
}

#define SET_INT(prop_ptr, name, bit, value)	\
	do {					\
		prop_ptr->_ ## name = value;	\
		prop_ptr->flags |= bit;		\
	} while (0)

#define SET_DATA(prop_ptr, name, bit, buf, buf_len)	\
	do {						\
		prop_ptr->_ ## name = buf;		\
		prop_ptr->_ ## name ## _len = buf_len;	\
		prop_ptr->flags |= bit;			\
	} while (0)

void m5_prop_payload_format_indicator(struct m5_prop *prop, uint8_t v)
{
	SET_INT(prop, payload_format_indicator,
		M5_2POW(REMAP_PAYLOAD_FORMAT_INDICATOR), v);
}

void m5_prop_publication_expiry_interval(struct m5_prop *prop, uint32_t v)
{
	SET_INT(prop, publication_expiry_interval,
		M5_2POW(REMAP_PUBLICATION_EXPIRY_INTERVAL), v);
}

void m5_prop_content_type(struct m5_prop *prop,
			  uint8_t *data, uint16_t data_len)
{
	SET_DATA(prop, content_type,
		 M5_2POW(REMAP_CONTENT_TYPE), data, data_len);
}

void m5_prop_response_topic(struct m5_prop *prop,
			    uint8_t *data, uint16_t data_len)
{
	SET_DATA(prop, response_topic, M5_2POW(REMAP_RESPONSE_TOPIC),
		 data, data_len);
}

void m5_prop_correlation_data(struct m5_prop *prop,
			      uint8_t *data, uint16_t data_len)
{
	SET_DATA(prop, correlation_data, M5_2POW(REMAP_CORRELATION_DATA),
		 data, data_len);
}

void m5_prop_subscription_id(struct m5_prop *prop, uint32_t v)
{
	SET_INT(prop, subscription_id,
		M5_2POW(REMAP_SUBSCRIPTION_IDENTIFIER), v);
}

void m5_prop_session_expiry_interval(struct m5_prop *prop, uint32_t v)
{
	SET_INT(prop, session_expiry_interval,
		M5_2POW(REMAP_SESSION_EXPIRY_INTERVAL), v);
}

void m5_prop_assigned_client_id(struct m5_prop *prop,
				uint8_t *data, uint16_t data_len)
{
	SET_DATA(prop, assigned_client_id,
		 M5_2POW(REMAP_ASSIGNED_CLIENT_IDENTIFIER), data, data_len);
}

void m5_prop_server_keep_alive(struct m5_prop *prop, uint16_t v)
{
	SET_INT(prop, server_keep_alive,
		M5_2POW(REMAP_SERVER_KEEP_ALIVE), v);
}

void m5_prop_auth_method(struct m5_prop *prop, uint8_t *d, uint16_t d_len)
{
	SET_DATA(prop, auth_method,
		 M5_2POW(REMAP_AUTH_METHOD), d, d_len);
}

void m5_prop_auth_data(struct m5_prop *prop, uint8_t *d, uint16_t d_len)
{
	SET_DATA(prop, auth_data, M5_2POW(REMAP_AUTH_DATA), d, d_len);
}

void m5_prop_request_problem_info(struct m5_prop *prop, uint8_t v)
{
	SET_INT(prop, request_problem_info,
		M5_2POW(REMAP_REQUEST_PROBLEM_INFORMATION),
		v > 0 ? 0x01 : 0x00);
}

void m5_prop_will_delay_interval(struct m5_prop *prop, uint32_t v)
{
	SET_INT(prop, will_delay_interval,
		M5_2POW(REMAP_WILL_DELAY_INTERVAL), v);
}

void m5_prop_request_response_info(struct m5_prop *prop, uint8_t v)
{
	SET_INT(prop, request_response_info,
		M5_2POW(REMAP_REQUEST_RESPONSE_INFORMATION),
		v > 0 ? 0x01 : 0x00);
}

void m5_prop_response_info(struct m5_prop *prop, uint8_t *d, uint16_t d_len)
{
	SET_DATA(prop, response_info,
		 M5_2POW(REMAP_RESPONSE_INFORMATION), d, d_len);
}

void m5_prop_server_reference(struct m5_prop *prop, uint8_t *d, uint16_t d_len)
{
	SET_DATA(prop, server_reference,
		 M5_2POW(REMAP_SERVER_REFERENCE), d, d_len);
}

void m5_prop_reason_str(struct m5_prop *prop, uint8_t *d, uint16_t d_len)
{
	SET_DATA(prop, reason_str, M5_2POW(REMAP_REASON_STR), d, d_len);
}

void m5_prop_receive_max(struct m5_prop *prop, uint16_t v)
{
	SET_INT(prop, receive_max, M5_2POW(REMAP_RECEIVE_MAXIMUM), v);
}

void m5_prop_topic_alias_max(struct m5_prop *prop, uint16_t v)
{
	SET_INT(prop, topic_alias_max,
		M5_2POW(REMAP_TOPIC_ALIAS_MAXIMUM), v);
}

void m5_prop_topic_alias(struct m5_prop *prop, uint16_t v)
{
	SET_INT(prop, topic_alias, M5_2POW(REMAP_TOPIC_ALIAS), v);
}

void m5_prop_max_qos(struct m5_prop *prop, uint8_t v)
{
	SET_INT(prop, max_qos, M5_2POW(REMAP_MAXIMUM_QOS), v);
}

void m5_prop_retain_available(struct m5_prop *prop, uint8_t v)
{
	SET_INT(prop, retain_available, M5_2POW(REMAP_RETAIN_AVAILABLE), v);
}

int m5_prop_add_user_prop(struct m5_prop *prop,
			  uint8_t *key, uint16_t key_len,
			  uint8_t *value, uint16_t value_len)
{
	struct m5_user_prop *user;

	if (prop == NULL) {
		return M5_INVALID_ARGUMENT;
	}

	if (prop->_user_len + 1 > M5_USER_PROP_SIZE) {
		if (M5_SKIP_ON_FULL_USER_PROP == 0) {
			return M5_USER_PROPERTY_ARRAY_IS_FULL;
		}

		return M5_SUCCESS;
	}

	prop->flags |=  M5_2POW(REMAP_USER_PROPERTY);

	user = &prop->_user_prop[prop->_user_len];
	user->key = key;
	user->key_len = key_len;
	user->value = value;
	user->value_len = value_len;

	prop->_user_len += 1;
	prop->_user_prop_wsize += 2 * M5_STR_LEN_SIZE + key_len + value_len;

	return M5_SUCCESS;
}

void m5_prop_max_packet_size(struct m5_prop *prop, uint32_t v)
{
	SET_INT(prop, max_packet_size,
		M5_2POW(REMAP_MAXIMUM_PACKET_SIZE), v);
}

void m5_prop_wildcard_subscription_available(struct m5_prop *prop, uint8_t v)
{
	SET_INT(prop, wildcard_subscription_available,
		M5_2POW(REMAP_WILDCARD_SUBSCRIPTION_AVAILABLE), v);
}

void m5_prop_subscription_id_available(struct m5_prop *prop, uint8_t v)
{
	SET_INT(prop, subscription_id_available,
		M5_2POW(REMAP_SUBSCRIPTION_IDENTIFIER_AVAILABLE), v);
}

void m5_prop_shared_subscription_available(struct m5_prop *prop, uint8_t v)
{
	SET_INT(prop, shared_subscription_available,
		M5_2POW(REMAP_SHARED_SUBSCRIPTION_AVAILABLE), v);
}

static int m5_len_prop_u8(struct m5_prop *prop, enum m5_prop_remap prop_id,
			  uint32_t *wsize)
{
	ARG_UNUSED(prop);
	ARG_UNUSED(prop_id);

	*wsize = PROP_ID_BYTE_WSIZE + 1;

	return M5_SUCCESS;
}

static int m5_len_prop_u16(struct m5_prop *prop, enum m5_prop_remap prop_id,
			   uint32_t *wsize)
{
	ARG_UNUSED(prop);
	ARG_UNUSED(prop_id);

	*wsize = PROP_ID_BYTE_WSIZE + 2;

	return M5_SUCCESS;
}

static int m5_len_prop_u32(struct m5_prop *prop, enum m5_prop_remap prop_id,
			   uint32_t *wsize)
{
	ARG_UNUSED(prop);
	ARG_UNUSED(prop_id);

	*wsize = PROP_ID_BYTE_WSIZE + 4;

	return M5_SUCCESS;
}

static int m5_len_prop_binary(struct m5_prop *prop, enum m5_prop_remap prop_id,
			      uint32_t *wsize)
{
	*wsize = PROP_ID_BYTE_WSIZE + M5_BINARY_LEN_SIZE;

	switch (prop_id) {
	case REMAP_CONTENT_TYPE:
		*wsize += prop->_content_type_len;
		break;
	case REMAP_RESPONSE_TOPIC:
		*wsize += prop->_response_topic_len;
		break;
	case REMAP_CORRELATION_DATA:
		*wsize += prop->_correlation_data_len;
		break;
	case REMAP_ASSIGNED_CLIENT_IDENTIFIER:
		*wsize += prop->_assigned_client_id_len;
		break;
	case REMAP_AUTH_METHOD:
		*wsize += prop->_auth_method_len;
		break;
	case REMAP_AUTH_DATA:
		*wsize += prop->_auth_data_len;
		break;
	case REMAP_RESPONSE_INFORMATION:
		*wsize += prop->_response_info_len;
		break;
	case REMAP_SERVER_REFERENCE:
		*wsize += prop->_server_reference_len;
		break;
	case REMAP_REASON_STR:
		*wsize += prop->_reason_str_len;
		break;
	default:
		return M5_INVALID_ARGUMENT;
	}

	return M5_SUCCESS;
}

static int m5_len_prop_varlen(struct m5_prop *prop, enum m5_prop_remap prop_id,
			      uint32_t *wsize)
{
	int rc;

	if (prop_id != REMAP_SUBSCRIPTION_IDENTIFIER) {
		return M5_INVALID_ARGUMENT;
	}

	rc = m5_rlen_wsize(prop->_subscription_id, wsize);
	if (rc != M5_SUCCESS) {
		return rc;
	}

	*wsize += PROP_ID_BYTE_WSIZE;

	return M5_SUCCESS;
}

static int m5_len_prop_user(struct m5_prop *prop, enum m5_prop_remap prop_id,
			    uint32_t *wsize)
{
	ARG_UNUSED(prop_id);

	*wsize = PROP_ID_BYTE_WSIZE * prop->_user_len + prop->_user_prop_wsize;

	return M5_SUCCESS;
}

static int buf2prop_u8(struct app_buf *buf, struct m5_prop *prop,
		       fcn_prop_u8 fcn_set_prop_value)
{
	if (APPBUF_FREE_READ_SPACE(buf) < 1) {
		return M5_NOT_ENOUGH_SPACE_IN_BUFFER;
	}

	fcn_set_prop_value(prop, buf->data[buf->offset]);
	buf->offset += 1;

	return M5_SUCCESS;
}

static int buf2prop_u16(struct app_buf *buf, struct m5_prop *prop,
			fcn_prop_u16 fcn_set_prop_value)
{
	if (APPBUF_FREE_READ_SPACE(buf) < 2) {
		return M5_NOT_ENOUGH_SPACE_IN_BUFFER;
	}

	fcn_set_prop_value(prop, m5_u16(buf->data + buf->offset));
	buf->offset += 2;

	return M5_SUCCESS;
}

static int buf2prop_u32(struct app_buf *buf, struct m5_prop *prop,
			fcn_prop_u32 fcn_set_prop_value)
{
	if (APPBUF_FREE_READ_SPACE(buf) < 4) {
		return M5_NOT_ENOUGH_SPACE_IN_BUFFER;
	}

	fcn_set_prop_value(prop, m5_u32(buf->data + buf->offset));
	buf->offset += 4;

	return M5_SUCCESS;
}

static int buf2prop_payload_format_indicator(struct app_buf *buf,
					     struct m5_prop *prop)
{
	return buf2prop_u8(buf, prop, m5_prop_payload_format_indicator);
}

static int buf2prop_request_problem_info(struct app_buf *buf,
					 struct m5_prop *prop)
{
	return buf2prop_u8(buf, prop, m5_prop_request_problem_info);
}

static int buf2prop_request_response_info(struct app_buf *buf,
					  struct m5_prop *prop)
{
	return buf2prop_u8(buf, prop, m5_prop_request_response_info);
}

static int buf2prop_max_qos(struct app_buf *buf, struct m5_prop *prop)
{
	return buf2prop_u8(buf, prop, m5_prop_max_qos);
}

static int buf2prop_retain_available(struct app_buf *buf, struct m5_prop *prop)
{
	return buf2prop_u8(buf, prop, m5_prop_retain_available);
}

static int buf2prop_wildcard_subscription_available(struct app_buf *buf,
				       struct m5_prop *prop)
{
	return buf2prop_u8(buf, prop, m5_prop_wildcard_subscription_available);
}

static int buf2prop_subscription_id_available(struct app_buf *buf,
					      struct m5_prop *prop)
{
	return buf2prop_u8(buf, prop, m5_prop_subscription_id_available);
}

static int buf2prop_shared_subscription_available(struct app_buf *buf,
					  struct m5_prop *prop)
{
	return buf2prop_u8(buf, prop, m5_prop_shared_subscription_available);
}

static int buf2prop_server_keep_alive(struct app_buf *buf, struct m5_prop *prop)
{
	return buf2prop_u16(buf, prop, m5_prop_server_keep_alive);
}

static int buf2prop_receive_max(struct app_buf *buf, struct m5_prop *prop)
{
	return buf2prop_u16(buf, prop, m5_prop_receive_max);
}

static int buf2prop_topic_alias_max(struct app_buf *buf, struct m5_prop *prop)
{
	return buf2prop_u16(buf, prop, m5_prop_topic_alias_max);
}

static int buf2prop_topic_alias(struct app_buf *buf, struct m5_prop *prop)
{
	return buf2prop_u16(buf, prop, m5_prop_topic_alias);
}

static int buf2prop_publication_expiry_interval(struct app_buf *buf,
						struct m5_prop *prop)
{
	return buf2prop_u32(buf, prop, m5_prop_publication_expiry_interval);
}

static int buf2prop_session_expiry_interval(struct app_buf *buf,
					    struct m5_prop *prop)
{
	return buf2prop_u32(buf, prop, m5_prop_session_expiry_interval);
}

static int buf2prop_will_delay_interval(struct app_buf *buf,
					struct m5_prop *prop)
{
	return buf2prop_u32(buf, prop, m5_prop_will_delay_interval);
}

static int buf2prop_max_packet_size(struct app_buf *buf, struct m5_prop *prop)
{
	return buf2prop_u32(buf, prop, m5_prop_max_packet_size);
}

static int buf2prop_binary(struct app_buf *buf, struct m5_prop *prop,
			   fcn_prop_binary fcn_set_prop_value)
{
	uint16_t data_len;
	uint8_t *data;
	int rc;

	rc = m5_unpack_binary(buf, &data, &data_len);
	if (rc != M5_SUCCESS) {
		return rc;
	}

	fcn_set_prop_value(prop, data, data_len);

	return M5_SUCCESS;
}

static int buf2prop_content_type(struct app_buf *buf, struct m5_prop *prop)
{
	return buf2prop_binary(buf, prop, m5_prop_content_type);
}

static int buf2prop_response_topic(struct app_buf *buf, struct m5_prop *prop)
{
	return buf2prop_binary(buf, prop, m5_prop_response_topic);
}

static int buf2prop_correlation_data(struct app_buf *buf, struct m5_prop *prop)
{
	return buf2prop_binary(buf, prop, m5_prop_correlation_data);
}

static int buf2prop_assigned_client_id(struct app_buf *buf,
				       struct m5_prop *prop)
{
	return buf2prop_binary(buf, prop, m5_prop_assigned_client_id);
}

static int buf2prop_auth_method(struct app_buf *buf, struct m5_prop *prop)
{
	return buf2prop_binary(buf, prop, m5_prop_auth_method);
}

static int buf2prop_auth_data(struct app_buf *buf, struct m5_prop *prop)
{
	return buf2prop_binary(buf, prop, m5_prop_auth_data);
}

static int buf2prop_response_info(struct app_buf *buf,
				  struct m5_prop *prop)
{
	return buf2prop_binary(buf, prop, m5_prop_response_info);
}

static int buf2prop_server_reference(struct app_buf *buf, struct m5_prop *prop)
{
	return buf2prop_binary(buf, prop, m5_prop_server_reference);
}

static int buf2prop_reason_str(struct app_buf *buf, struct m5_prop *prop)
{
	return buf2prop_binary(buf, prop, m5_prop_reason_str);
}

static int buf2prop_subscription_id(struct app_buf *buf, struct m5_prop *prop)
{
	uint32_t prop_val;
	uint32_t prop_len;
	int rc;

	rc = m5_decode_int(buf, &prop_val, &prop_len);
	if (rc != M5_SUCCESS) {
		return rc;
	}

	m5_prop_subscription_id(prop, prop_val);

	return M5_SUCCESS;
}

static int buf2prop_user_prop(struct app_buf *buf, struct m5_prop *prop)
{
	uint16_t value_len;
	uint16_t key_len;
	uint8_t *value;
	uint8_t *key;
	int rc;

	rc = m5_unpack_binary(buf, &key, &key_len);
	if (rc != M5_SUCCESS) {
		return rc;
	}

	rc = m5_unpack_binary(buf, &value, &value_len);
	if (rc != M5_SUCCESS) {
		return rc;
	}

	rc = m5_prop_add_user_prop(prop, key, key_len, value, value_len);
	return rc;
}

static void prop2buf_payload_format_indicator(struct app_buf *buf,
					      struct m5_prop *prop)
{
	m5_add_u8(buf, PAYLOAD_FORMAT_INDICATOR);
	m5_add_u8(buf, prop->_payload_format_indicator);
}

static void prop2buf_request_problem_info(struct app_buf *buf,
					  struct m5_prop *prop)
{
	m5_add_u8(buf, REQUEST_PROBLEM_INFORMATION);
	m5_add_u8(buf, prop->_request_problem_info);
}

static void prop2buf_request_response_info(struct app_buf *buf,
					   struct m5_prop *prop)
{
	m5_add_u8(buf, REQUEST_RESPONSE_INFORMATION);
	m5_add_u8(buf, prop->_request_response_info);
}

static void prop2buf_max_qos(struct app_buf *buf, struct m5_prop *prop)
{
	m5_add_u8(buf, MAXIMUM_QOS);
	m5_add_u8(buf, prop->_max_qos);
}

static void prop2buf_retain_available(struct app_buf *buf, struct m5_prop *prop)
{
	m5_add_u8(buf, RETAIN_AVAILABLE);
	m5_add_u8(buf, prop->_retain_available);
}

static void prop2buf_wildcard_subscription_available(struct app_buf *buf,
					  struct m5_prop *prop)
{
	m5_add_u8(buf, WILDCARD_SUBSCRIPTION_AVAILABLE);
	m5_add_u8(buf, prop->_wildcard_subscription_available);
}

static void prop2buf_subscription_id_available(struct app_buf *buf,
				       struct m5_prop *prop)
{
	m5_add_u8(buf, SUBSCRIPTION_IDENTIFIER_AVAILABLE);
	m5_add_u8(buf, prop->_subscription_id_available);
}

static void prop2buf_shared_subscription_available(struct app_buf *buf,
					   struct m5_prop *prop)
{
	m5_add_u8(buf, SHARED_SUBSCRIPTION_AVAILABLE);
	m5_add_u8(buf, prop->_shared_subscription_available);
}

static void prop2buf_server_keep_alive(struct app_buf *buf,
				       struct m5_prop *prop)
{
	m5_add_u8(buf, SERVER_KEEP_ALIVE);
	m5_add_u16(buf, prop->_server_keep_alive);
}

static void prop2buf_receive_max(struct app_buf *buf, struct m5_prop *prop)
{
	m5_add_u8(buf, RECEIVE_MAXIMUM);
	m5_add_u16(buf, prop->_receive_max);
}

static void prop2buf_topic_alias_max(struct app_buf *buf, struct m5_prop *prop)
{
	m5_add_u8(buf, TOPIC_ALIAS_MAXIMUM);
	m5_add_u16(buf, prop->_topic_alias_max);
}

static void prop2buf_topic_alias(struct app_buf *buf, struct m5_prop *prop)
{
	m5_add_u8(buf, TOPIC_ALIAS);
	m5_add_u16(buf, prop->_topic_alias);
}

static void prop2buf_publication_expiry_interval(struct app_buf *buf,
						 struct m5_prop *prop)
{
	m5_add_u8(buf, PUBLICATION_EXPIRY_INTERVAL);
	m5_add_u32(buf, prop->_publication_expiry_interval);
}

static void prop2buf_session_expiry_interval(struct app_buf *buf,
					     struct m5_prop *prop)
{
	m5_add_u8(buf, SESSION_EXPIRY_INTERVAL);
	m5_add_u32(buf, prop->_session_expiry_interval);
}

static void prop2buf_will_delay_interval(struct app_buf *buf,
					 struct m5_prop *prop)
{
	m5_add_u8(buf, WILL_DELAY_INTERVAL);
	m5_add_u32(buf, prop->_will_delay_interval);
}

static void prop2buf_max_packet_size(struct app_buf *buf, struct m5_prop *prop)
{
	m5_add_u8(buf, MAXIMUM_PACKET_SIZE);
	m5_add_u32(buf, prop->_max_packet_size);
}

static void prop2buf_content_type(struct app_buf *buf, struct m5_prop *prop)
{
	m5_add_u8(buf, CONTENT_TYPE);
	m5_add_binary(buf, prop->_content_type, prop->_content_type_len);
}

static void prop2buf_response_topic(struct app_buf *buf, struct m5_prop *prop)
{
	m5_add_u8(buf, RESPONSE_TOPIC);
	m5_add_binary(buf, prop->_response_topic, prop->_response_topic_len);
}

static void prop2buf_correlation_data(struct app_buf *buf, struct m5_prop *prop)
{
	m5_add_u8(buf, CORRELATION_DATA);
	m5_add_binary(buf, prop->_correlation_data,
		      prop->_correlation_data_len);
}

static void prop2buf_assigned_client_id(struct app_buf *buf,
					struct m5_prop *prop)
{
	m5_add_u8(buf, ASSIGNED_CLIENT_IDENTIFIER);
	m5_add_binary(buf, prop->_assigned_client_id,
		      prop->_assigned_client_id_len);
}

static void prop2buf_auth_method(struct app_buf *buf, struct m5_prop *prop)
{
	m5_add_u8(buf, AUTH_METHOD);
	m5_add_binary(buf, prop->_auth_method, prop->_auth_method_len);
}

static void prop2buf_auth_data(struct app_buf *buf, struct m5_prop *prop)
{
	m5_add_u8(buf, AUTH_DATA);
	m5_add_binary(buf, prop->_auth_data, prop->_auth_data_len);
}

static void prop2buf_response_info(struct app_buf *buf, struct m5_prop *prop)
{
	m5_add_u8(buf, RESPONSE_INFORMATION);
	m5_add_binary(buf, prop->_response_info, prop->_response_info_len);
}

static void prop2buf_server_reference(struct app_buf *buf, struct m5_prop *prop)
{
	m5_add_u8(buf, SERVER_REFERENCE);
	m5_add_binary(buf, prop->_server_reference,
		      prop->_server_reference_len);
}

static void prop2buf_reason_string(struct app_buf *buf, struct m5_prop *prop)
{
	m5_add_u8(buf, REASON_STR);
	m5_add_binary(buf, prop->_reason_str, prop->_reason_str_len);
}

static void prop2buf_subscription_id(struct app_buf *buf, struct m5_prop *prop)
{
	m5_add_u8(buf, SUBSCRIPTION_IDENTIFIER);
	m5_encode_int(buf, prop->_subscription_id);
}

static void prop2buf_user_prop(struct app_buf *buf, struct m5_prop *prop)
{
	uint8_t i;

	for (i = 0; i < prop->_user_len; i++) {
		m5_add_u8(buf, USER_PROPERTY);
		m5_add_binary(buf, prop->_user_prop[i].key,
			      prop->_user_prop[i].key_len);
		m5_add_binary(buf, prop->_user_prop[i].value,
			      prop->_user_prop[i].value_len);
	}
}

static struct m5_prop_conf m5_prop_conf[] = {
	{ 0 },


	/* PAYLOAD_FORMAT_INDICATOR */
	{.valid_msgs = M5_2POW(M5_PKT_PUBLISH),
	 .wire_size = m5_len_prop_u8,
	 .buf2prop = buf2prop_payload_format_indicator,
	 .prop2buf = prop2buf_payload_format_indicator},
	/* REQUEST_PROBLEM_INFORMATION */
	{.valid_msgs = M5_2POW(M5_PKT_CONNECT),
	 .wire_size = m5_len_prop_u8,
	 .buf2prop = buf2prop_request_problem_info,
	 .prop2buf = prop2buf_request_problem_info},
	/* REQUEST_RESPONSE_INFORMATION */
	{.valid_msgs = M5_2POW(M5_PKT_CONNECT),
	 .wire_size = m5_len_prop_u8,
	 .buf2prop = buf2prop_request_response_info,
	 .prop2buf = prop2buf_request_response_info},
	/* MAXIMUM_QOS */
	{.valid_msgs = M5_2POW(M5_PKT_CONNACK),
	 .wire_size = m5_len_prop_u8,
	 .buf2prop = buf2prop_max_qos,
	 .prop2buf = prop2buf_max_qos},
	/* RETAIN_AVAILABLE */
	{.valid_msgs = M5_2POW(M5_PKT_CONNACK),
	 .wire_size = m5_len_prop_u8,
	 .buf2prop = buf2prop_retain_available,
	 .prop2buf = prop2buf_retain_available},
	/* WILDCARD_SUBSCRIPTION_AVAILABLE */
	{.valid_msgs = M5_2POW(M5_PKT_CONNACK),
	 .wire_size = m5_len_prop_u8,
	 .buf2prop = buf2prop_wildcard_subscription_available,
	 .prop2buf = prop2buf_wildcard_subscription_available},
	/* SUBSCRIPTION_IDENTIFIER_AVAILABLE */
	{.valid_msgs = M5_2POW(M5_PKT_CONNACK),
	 .wire_size = m5_len_prop_u8,
	 .buf2prop = buf2prop_subscription_id_available,
	 .prop2buf = prop2buf_subscription_id_available},
	/* SHARED_SUBSCRIPTION_AVAILABLE */
	{.valid_msgs = M5_2POW(M5_PKT_CONNACK),
	 .wire_size = m5_len_prop_u8,
	 .buf2prop = buf2prop_shared_subscription_available,
	 .prop2buf = prop2buf_shared_subscription_available},


	/* SERVER_KEEP_ALIVE */
	{.valid_msgs = M5_2POW(M5_PKT_CONNACK),
	 .wire_size = m5_len_prop_u16,
	 .buf2prop = buf2prop_server_keep_alive,
	 .prop2buf = prop2buf_server_keep_alive},
	/* RECEIVE_MAXIMUM */
	{.valid_msgs = M5_2POW(M5_PKT_CONNECT) |
		 M5_2POW(M5_PKT_CONNACK),
	 .wire_size = m5_len_prop_u16,
	 .buf2prop = buf2prop_receive_max,
	 .prop2buf = prop2buf_receive_max},
	/* TOPIC_ALIAS_MAXIMUM */
	{.valid_msgs = M5_2POW(M5_PKT_CONNECT) |
		 M5_2POW(M5_PKT_CONNACK),
	 .wire_size = m5_len_prop_u16,
	 .buf2prop = buf2prop_topic_alias_max,
	 .prop2buf = prop2buf_topic_alias_max},
	/* TOPIC_ALIAS */
	{.valid_msgs = M5_2POW(M5_PKT_PUBLISH),
	 .wire_size = m5_len_prop_u16,
	 .buf2prop = buf2prop_topic_alias,
	 .prop2buf = prop2buf_topic_alias},


	/* PUBLICATION_EXPIRY_INTERVAL */
	{.valid_msgs = M5_2POW(M5_PKT_PUBLISH),
	 .wire_size = m5_len_prop_u32,
	 .buf2prop = buf2prop_publication_expiry_interval,
	 .prop2buf = prop2buf_publication_expiry_interval},
	/* SESSION_EXPIRY_INTERVAL */
	{.valid_msgs = M5_2POW(M5_PKT_CONNECT) |
		 M5_2POW(M5_PKT_DISCONNECT),
	 .wire_size = m5_len_prop_u32,
	 .buf2prop = buf2prop_session_expiry_interval,
	 .prop2buf = prop2buf_session_expiry_interval},
	/* WILL_DELAY_INTERVAL */
	{.valid_msgs = M5_2POW(M5_PKT_CONNECT),
	 .wire_size = m5_len_prop_u32,
	 .buf2prop = buf2prop_will_delay_interval,
	 .prop2buf = prop2buf_will_delay_interval},
	/* MAXIMUM_PACKET_SIZE */
	{.valid_msgs = M5_2POW(M5_PKT_CONNECT) |
		 M5_2POW(M5_PKT_CONNACK),
	 .wire_size = m5_len_prop_u32,
	 .buf2prop = buf2prop_max_packet_size,
	 .prop2buf = prop2buf_max_packet_size},


	/* CONTENT_TYPE */
	{.valid_msgs = M5_2POW(M5_PKT_PUBLISH),
	 .wire_size = m5_len_prop_binary,
	 .buf2prop = buf2prop_content_type,
	 .prop2buf = prop2buf_content_type},
	/* RESPONSE_TOPIC */
	{.valid_msgs = M5_2POW(M5_PKT_PUBLISH),
	 .wire_size = m5_len_prop_binary,
	 .buf2prop = buf2prop_response_topic,
	 .prop2buf = prop2buf_response_topic},
	/* CORRELATION_DATA */
	{.valid_msgs = M5_2POW(M5_PKT_PUBLISH),
	 .wire_size = m5_len_prop_binary,
	 .buf2prop = buf2prop_correlation_data,
	 .prop2buf = prop2buf_correlation_data},
	/* ASSIGNED_CLIENT_IDENTIFIER */
	{.valid_msgs = M5_2POW(M5_PKT_CONNACK),
	 .wire_size = m5_len_prop_binary,
	 .buf2prop = buf2prop_assigned_client_id,
	 .prop2buf = prop2buf_assigned_client_id},
	/* AUTH_METHOD */
	{.valid_msgs = M5_2POW(M5_PKT_CONNECT) |
		 M5_2POW(M5_PKT_CONNACK) |
		 M5_2POW(M5_PKT_AUTH),
	 .wire_size = m5_len_prop_binary,
	 .buf2prop = buf2prop_auth_method,
	 .prop2buf = prop2buf_auth_method},
	/* AUTH_DATA */
	{.valid_msgs = M5_2POW(M5_PKT_CONNECT) |
		 M5_2POW(M5_PKT_CONNACK) |
		 M5_2POW(M5_PKT_AUTH),
	 .wire_size = m5_len_prop_binary,
	 .buf2prop = buf2prop_auth_data,
	 .prop2buf = prop2buf_auth_data},
	/* RESPONSE_INFORMATION */
	{.valid_msgs = M5_2POW(M5_PKT_CONNACK),
	 .wire_size = m5_len_prop_binary,
	 .buf2prop = buf2prop_response_info,
	 .prop2buf = prop2buf_response_info},
	/* SERVER_REFERENCE */
	{.valid_msgs = M5_2POW(M5_PKT_CONNACK) |
		 M5_2POW(M5_PKT_DISCONNECT),
	 .wire_size = m5_len_prop_binary,
	 .buf2prop = buf2prop_server_reference,
	 .prop2buf = prop2buf_server_reference},
	/* REASON_STR */
	{.valid_msgs = M5_2POW(M5_PKT_CONNACK) |
		 M5_2POW(M5_PKT_PUBACK) |
		 M5_2POW(M5_PKT_PUBREC) |
		 M5_2POW(M5_PKT_PUBREL) |
		 M5_2POW(M5_PKT_PUBCOMP) |
		 M5_2POW(M5_PKT_SUBACK) |
		 M5_2POW(M5_PKT_UNSUBACK) |
		 M5_2POW(M5_PKT_DISCONNECT) |
		 M5_2POW(M5_PKT_AUTH),
	 .wire_size = m5_len_prop_binary,
	 .buf2prop = buf2prop_reason_str,
	 .prop2buf = prop2buf_reason_string},


	/* SUBSCRIPTION_IDENTIFIER */
	{.valid_msgs = M5_2POW(M5_PKT_PUBLISH) |
		 M5_2POW(M5_PKT_SUBSCRIBE),
	 .wire_size = m5_len_prop_varlen,
	 .buf2prop = buf2prop_subscription_id,
	 .prop2buf = prop2buf_subscription_id},


	/* USER_PROPERTY */
	{.valid_msgs = M5_2POW(M5_PKT_CONNECT) |
		 M5_2POW(M5_PKT_CONNACK) |
		 M5_2POW(M5_PKT_PUBLISH) |
		 M5_2POW(M5_PKT_PUBACK) |
		 M5_2POW(M5_PKT_PUBREC) |
		 M5_2POW(M5_PKT_PUBREL) |
		 M5_2POW(M5_PKT_PUBCOMP) |
		 M5_2POW(M5_PKT_SUBACK) |
		 M5_2POW(M5_PKT_UNSUBACK) |
		 M5_2POW(M5_PKT_DISCONNECT) |
		 M5_2POW(M5_PKT_AUTH),
	 .wire_size = m5_len_prop_user,
	 .buf2prop = buf2prop_user_prop,
	 .prop2buf = prop2buf_user_prop}
	};

static int m5_prop_pkt_validate(enum m5_prop_remap prop_id,
				enum m5_pkt_type pkt_type)
{
	int found;

	if (prop_id <= 0 || prop_id >= M5_REMAP_PROP_LEN) {
		return M5_INVALID_ARGUMENT;
	}

	found = (m5_prop_conf[prop_id].valid_msgs & M5_2POW(pkt_type));
	if (found == 0) {
		return M5_INVALID_ARGUMENT;
	}

	return M5_SUCCESS;
}

static int m5_prop_wsize(enum m5_pkt_type msg_type, struct m5_prop *prop,
			 uint32_t *wire_size)
{
	int (*fcn_wsize)(struct m5_prop *, enum m5_prop_remap, uint32_t *);
	uint32_t flags;
	int rc;

	*wire_size = 0;
	if (prop == NULL) {
		return M5_SUCCESS;
	}

	flags = prop->flags;
	while (flags > 0) {
		uint32_t remainder = flags & (flags - 1);
		uint32_t remap_prop_id = __builtin_ffs(flags ^ remainder) - 1;
		uint32_t prop_wsize;

		rc = m5_prop_pkt_validate(remap_prop_id, msg_type);
		if (rc != M5_SUCCESS) {
			return rc;
		}

		fcn_wsize = m5_prop_conf[remap_prop_id].wire_size;
		rc = fcn_wsize(prop, remap_prop_id, &prop_wsize);
		if (rc != M5_SUCCESS) {
			return rc;
		}

		*wire_size += prop_wsize;

		flags = remainder;
	}

	return M5_SUCCESS;
}

static int m5_pack_prop(struct app_buf *buf, struct m5_prop *prop,
			uint32_t wire_size)
{
	void (*fcn_write)(struct app_buf *, struct m5_prop *);
	uint32_t flags;
	int rc;

	rc = m5_encode_int(buf, wire_size);
	if (rc != M5_SUCCESS) {
		return rc;
	}

	if (prop == NULL || wire_size == 0) {
		return M5_SUCCESS;
	}

	if (APPBUF_FREE_WRITE_SPACE(buf) < wire_size) {
		return M5_NOT_ENOUGH_SPACE_IN_BUFFER;
	}

	flags = prop->flags;
	while (flags > 0) {
		uint32_t remainder = flags & (flags - 1);
		uint32_t remap_prop_id = __builtin_ffs(flags ^ remainder) - 1;

		fcn_write = m5_prop_conf[remap_prop_id].prop2buf;
		fcn_write(buf, prop);

		flags = remainder;
	}

	return M5_SUCCESS;
}

int m5_unpack_ignore(struct m5_ctx *ctx, struct app_buf *buf)
{
	uint32_t rlen_wsize;
	uint32_t rlen;
	int rc;

	if (buf == NULL || APPBUF_FREE_READ_SPACE(buf) < 2) {
		rc = M5_NOT_ENOUGH_SPACE_IN_BUFFER;
		goto lb_exit;
	}

	/* skip fixed header */
	buf->offset += 1;

	rc = m5_decode_int(buf, &rlen, &rlen_wsize);
	if (rc != M5_SUCCESS) {
		rc = M5_INVALID_REMLEN_VBI;
		goto lb_exit;
	}

	if (APPBUF_FREE_READ_SPACE(buf) < rlen) {
		rc = M5_NOT_ENOUGH_SPACE_IN_BUFFER;
		goto lb_exit;
	}

	/* skip var header and payload (if any) */
	buf->offset += rlen;

	rc = M5_SUCCESS;
lb_exit:
	m5_ctx_status(ctx, rc);

	return rc;
}

static int m5_connect_payload_wsize(struct m5_connect *msg,
				    uint32_t *wire_size)
{
	if (msg->client_id_len < M5_CLIENTID_MIN_LEN ||
	    msg->client_id_len > M5_CLIENTID_MAX_LEN) {
		return M5_INVALID_ARGUMENT;
	}

	*wire_size = M5_STR_LEN_SIZE  + msg->client_id_len;

	if (msg->will_msg_len > 0 && msg->will_topic_len > 0) {
		*wire_size += M5_STR_LEN_SIZE  + msg->will_topic_len +
			      M5_BINARY_LEN_SIZE + msg->will_msg_len;
	} else if (msg->will_msg_len  + msg->will_topic_len != 0) {
		return M5_INVALID_ARGUMENT;
	}

	if (msg->user_name_len > 0) {
		*wire_size += M5_STR_LEN_SIZE + msg->user_name_len;
	}

	if (msg->password_len > 0) {
		*wire_size += M5_BINARY_LEN_SIZE + msg->password_len;
	}

	return M5_SUCCESS;
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

	return M5_SUCCESS;
}

static int m5_unpack_prop_id(struct app_buf *buf, uint8_t *id)
{
	if (APPBUF_FREE_READ_SPACE(buf) < PROP_ID_BYTE_WSIZE) {
		return M5_INVALID_ARGUMENT;
	}

	*id = *(buf->data + buf->offset);
	buf->offset += PROP_ID_BYTE_WSIZE;

	return M5_SUCCESS;
}

static int m5_unpack_prop_field(struct app_buf *buf, struct m5_prop *prop,
				enum m5_pkt_type msg)
{
	uint8_t prop_id;
	int rc;

	rc = m5_unpack_prop_id(buf, &prop_id);
	if (rc != M5_SUCCESS) {
		return rc;
	}

	if (prop_id < 1 || prop_id >= M5_PROP_LEN) {
		return M5_INVALID_ARGUMENT;
	}

	prop_id = prop_2_remap[prop_id];
	rc = m5_prop_pkt_validate(prop_id, msg);
	if (rc != M5_SUCCESS) {
		/* Property is invalid for this MQTT msg */
		return rc;
	}

	/* TODO: only allow USER_PROPERTY to be repeated inside the property */
	if (prop_id != REMAP_USER_PROPERTY) {
		if ((prop->flags & M5_2POW(prop_id)) > 0) {
			return M5_INVALID_ARGUMENT;
		}
	}

	return m5_prop_conf[prop_id].buf2prop(buf, prop);
}

static int m5_unpack_prop(struct app_buf *buf, struct m5_prop *prop,
			  enum m5_pkt_type msg)
{
	long long int remaining;
	uint32_t prop_len_wsize;
	uint32_t prop_len;
	int rc;

	/* Prop len and len's wire size */
	rc = m5_decode_int(buf, &prop_len, &prop_len_wsize);
	if (rc != M5_SUCCESS || (prop_len > 0 && prop == NULL)) {
		return M5_INVALID_ARGUMENT;
	}

	if (prop_len == 0) {
		return M5_SUCCESS;
	}

	if (APPBUF_FREE_READ_SPACE(buf) < prop_len) {
		return M5_NOT_ENOUGH_SPACE_IN_BUFFER;
	}

	remaining = prop_len;
	do {
		size_t offset;

		offset = buf->offset;
		rc = m5_unpack_prop_field(buf, prop, msg);
		if (rc != M5_SUCCESS) {
			return rc;
		}

		remaining -= buf->offset - offset;
	} while (remaining > 0);

	if (remaining != 0) {
		return M5_INVALID_ARGUMENT;
	}

	return M5_SUCCESS;
}

static int m5_buffer_set(uint8_t **dst, uint16_t *dst_len, struct app_buf *buf)
{
	if (APPBUF_FREE_READ_SPACE(buf) < M5_BINARY_LEN_SIZE) {
		return M5_NOT_ENOUGH_SPACE_IN_BUFFER;
	}

	/* get buffer len */
	*dst_len = m5_u16(buf->data + buf->offset);
	buf->offset += M5_BINARY_LEN_SIZE;

	*dst = buf->data + buf->offset;
	if (APPBUF_FREE_READ_SPACE(buf) < *dst_len) {
		return M5_NOT_ENOUGH_SPACE_IN_BUFFER;
	}

	buf->offset += *dst_len;

	return M5_SUCCESS;
}

static int m5_unpack_proto_name(struct app_buf *buf)
{
	uint8_t *data = buf->data + buf->offset;

	if (APPBUF_FREE_READ_SPACE(buf) < M5_PROTO_NAME_LEN) {
		return M5_NOT_ENOUGH_SPACE_IN_BUFFER;
	}

	if (data[0] != 0 || data[1] != 4 || data[2] != 'M' ||
	    data[3] != 'Q' || data[4] != 'T' || data[5] != 'T') {
		return M5_INVALID_ARGUMENT;
	}

	buf->offset += M5_PROTO_NAME_LEN;

	return M5_SUCCESS;
}

static int m5_connect_flags_clean_start(uint8_t flags)
{
	return (flags & (1 << 1)) ? 1 : 0;
}

static int m5_connect_flags_will_msg(uint8_t flags)
{
	return (flags & (1 << 2)) ? 1 : 0;
}

static int m5_connect_flags_will_qos(uint8_t flags)
{
	return (flags & (3 << 3)) >> 3;
}

static int m5_connect_flags_will_retain(uint8_t flags)
{
	return (flags & (1 << 5)) ? 1 : 0;
}

static int m5_connect_flags_password(uint8_t flags)
{
	return (flags & (1 << 6)) ? 1 : 0;
}

static int m5_connect_flags_username(uint8_t flags)
{
	return (flags & (1 << 7)) ? 1 : 0;
}

static int m5_unpack_connect_flags(struct app_buf *buf, struct m5_connect *msg)
{
	if (APPBUF_FREE_READ_SPACE(buf) < M5_CONNECT_FLAGS_WSIZE) {
		return M5_NOT_ENOUGH_SPACE_IN_BUFFER;
	}

	msg->flags = *APPBUF_DATAPTR_CURRENT(buf);
	if ((msg->flags & 0x01) != 0x00) {
		return M5_INVALID_ARGUMENT;
	}

	msg->clean_start = m5_connect_flags_clean_start(msg->flags);
	msg->will_qos = m5_connect_flags_will_qos(msg->flags);
	msg->will_retain = m5_connect_flags_will_retain(msg->flags);

	buf->offset += M5_CONNECT_FLAGS_WSIZE;

	return M5_SUCCESS;
}

static int m5_unpack_connect_payload(struct app_buf *buf,
				     struct m5_connect *msg)
{
	int  rc;

	rc = m5_buffer_set(&msg->client_id, &msg->client_id_len, buf);
	if (rc != M5_SUCCESS) {
		return rc;
	}

	if (m5_connect_flags_will_msg(msg->flags)) {
		rc = m5_buffer_set(&msg->will_topic, &msg->will_topic_len, buf);
		if (rc != M5_SUCCESS) {
			return rc;
		}

		rc = m5_buffer_set(&msg->will_msg, &msg->will_msg_len, buf);
		if (rc != M5_SUCCESS) {
			return rc;
		}
	}

	if (m5_connect_flags_username(msg->flags)) {
		rc = m5_buffer_set(&msg->user_name, &msg->user_name_len, buf);
		if (rc != M5_SUCCESS) {
			return rc;
		}
	}

	if (m5_connect_flags_password(msg->flags)) {
		rc = m5_buffer_set(&msg->password, &msg->password_len, buf);
		if (rc != M5_SUCCESS) {
			return rc;
		}
	}

	return M5_SUCCESS;
}

static int m5_unpack_proto_version(struct app_buf *buf)
{
	if (APPBUF_FREE_READ_SPACE(buf) < 1 || buf->data[buf->offset] != M5_5) {
		return M5_INVALID_ARGUMENT;
	}

	buf->offset += 1;

	return M5_SUCCESS;
}

static int m5_unpack_connect_keep_alive(struct app_buf *buf,
					struct m5_connect *msg)
{
	if (APPBUF_FREE_READ_SPACE(buf) < 2) {
		return M5_NOT_ENOUGH_SPACE_IN_BUFFER;
	}

	msg->keep_alive = m5_u16(buf->data + buf->offset);
	buf->offset += M5_INT_LEN_SIZE;

	return M5_SUCCESS;
}

static int m5_publish_flags(struct m5_publish *msg, uint8_t *flags)
{
	if (msg->qos >= 0x03 || msg->dup > 0x01 || msg->retain > 0x01) {
		return M5_INVALID_ARGUMENT;
	}

	*flags = (msg->dup << 3);
	*flags |= (msg->qos << 1);
	*flags |= (msg->retain);

	return M5_SUCCESS;
}

static uint32_t bin_wsize(uint32_t bin_len)
{
	return M5_BINARY_LEN_SIZE + bin_len;
}

static uint32_t str_wsize(uint32_t str_len)
{
	return bin_wsize(str_len);
}

static int m5_unpack_publish_flags(struct m5_publish *msg, uint8_t flags)
{
	msg->retain = flags & 0x1;
	msg->qos = (flags & (0x03 << 1)) >> 1;
	msg->dup = (flags & 0x01 << 3) >> 3;
	if (msg->qos == 0x03) {
		return M5_INVALID_ARGUMENT;
	}

	return M5_SUCCESS;
}

static int m5_pub_reason_code(enum m5_pkt_type pkt_type, uint8_t reason_code)
{
	switch (pkt_type) {
	default:
		return M5_INVALID_ARGUMENT;
	case M5_PKT_PUBACK:
	case M5_PKT_PUBREC:
		switch (reason_code) {
		default:
			return M5_INVALID_ARGUMENT;
		case M5_RC_SUCCESS:
		case M5_RC_NO_MATCHING_SUBSCRIBERS:
		case M5_RC_UNSPECIFIED_ERROR:
		case M5_RC_IMPLEMENTATION_SPECIFIC_ERROR:
		case M5_RC_NOT_AUTHORIZED:
		case M5_RC_TOPIC_NAME_INVALID:
		case M5_RC_PACKET_IDENTIFIER_IN_USE:
		case M5_RC_QUOTA_EXCEEDED:
		case M5_RC_PAYLOAD_FORMAT_INVALID:
			return M5_SUCCESS;
		}
	case M5_PKT_PUBREL:
	case M5_PKT_PUBCOMP:
		switch (reason_code) {
		default:
			return M5_INVALID_ARGUMENT;
		case M5_RC_SUCCESS:
		case M5_RC_PACKET_IDENTIFIER_NOT_FOUND:
			return M5_SUCCESS;
		}
	}

	return M5_SUCCESS;
}

static int m5_pack_pub_msgs(struct m5_ctx *ctx, struct app_buf *buf,
			    struct m5_pub_response *msg, struct m5_prop *prop,
			    enum m5_pkt_type pkt_type);


int m5_pack_puback(struct m5_ctx *ctx, struct app_buf *buf,
		   struct m5_pub_response *msg, struct m5_prop *prop)
{
	return m5_pack_pub_msgs(ctx, buf, msg, prop, M5_PKT_PUBACK);
}

int m5_pack_pubrec(struct m5_ctx *ctx, struct app_buf *buf,
		   struct m5_pub_response *msg, struct m5_prop *prop)
{
	return m5_pack_pub_msgs(ctx, buf, msg, prop, M5_PKT_PUBREC);
}

int m5_pack_pubrel(struct m5_ctx *ctx, struct app_buf *buf,
		   struct m5_pub_response *msg, struct m5_prop *prop)
{
	return m5_pack_pub_msgs(ctx, buf, msg, prop, M5_PKT_PUBREL);
}

int m5_pack_pubcomp(struct m5_ctx *ctx, struct app_buf *buf,
		    struct m5_pub_response *msg, struct m5_prop *prop)
{
	return m5_pack_pub_msgs(ctx, buf, msg, prop, M5_PKT_PUBCOMP);
}

static int m5_unpack_pub_msgs(struct m5_ctx *ctx, struct app_buf *buf,
			      struct m5_pub_response *msg, struct m5_prop *prop,
			      enum m5_pkt_type pkt_type);

int m5_unpack_puback(struct m5_ctx *ctx, struct app_buf *buf,
		     struct m5_pub_response *msg, struct m5_prop *prop)
{
	return m5_unpack_pub_msgs(ctx, buf, msg, prop, M5_PKT_PUBACK);
}

int m5_unpack_pubrec(struct m5_ctx *ctx, struct app_buf *buf,
		     struct m5_pub_response *msg, struct m5_prop *prop)
{
	return m5_unpack_pub_msgs(ctx, buf, msg, prop, M5_PKT_PUBREC);
}

int m5_unpack_pubrel(struct m5_ctx *ctx, struct app_buf *buf,
		     struct m5_pub_response *msg, struct m5_prop *prop)
{
	return m5_unpack_pub_msgs(ctx, buf, msg, prop, M5_PKT_PUBREL);
}

int m5_unpack_pubcomp(struct m5_ctx *ctx, struct app_buf *buf,
		      struct m5_pub_response *msg, struct m5_prop *prop)
{
	return m5_unpack_pub_msgs(ctx, buf, msg, prop, M5_PKT_PUBCOMP);
}

static int m5_topics_wsize(struct m5_topics *topics, uint32_t *wire_size)
{
	uint8_t i;

	*wire_size = 0;
	for (i = 0; i < topics->items; i++) {
		*wire_size += M5_STR_LEN_SIZE + topics->len[i];
	}

	if (*wire_size == 0) {
		return M5_INVALID_ARGUMENT;
	}

	return M5_SUCCESS;
}

static int m5_pack_subscribe_payload(struct app_buf *buf,
				     struct m5_subscribe *msg)
{
	uint8_t i;

	for (i = 0; i < msg->topics.items; i++) {
		uint8_t options = msg->options[i];

		if ((options & 0x03) == 0x03 || (options & 0xC0) != 0) {
			return M5_INVALID_ARGUMENT;
		}

		m5_add_binary(buf, msg->topics.topics[i], msg->topics.len[i]);
		m5_add_u8(buf, options);
	}

	return M5_SUCCESS;
}

static int m5_unpack_subscribe_payload(struct app_buf *buf,
				       struct m5_subscribe *msg,
				       uint32_t payload_wsize)
{
	uint32_t initial = buf->offset;
	uint8_t i = 0;
	int rc;

	do {
		if (i >= msg->topics.size) {
			return M5_NOT_ENOUGH_SPACE_IN_BUFFER;
		}

		rc = m5_unpack_binary(buf, &msg->topics.topics[i],
				      &msg->topics.len[i]);
		if (rc != M5_SUCCESS) {
			return rc;
		}

		rc = m5_unpack_u8(buf, &msg->options[i]);
		if (rc != M5_SUCCESS) {
			return rc;
		}

		i++;
	} while (buf->offset - initial < payload_wsize);

	msg->topics.items = i;

	if (buf->offset - initial != payload_wsize) {
		return M5_INVALID_ARGUMENT;
	}

	return M5_SUCCESS;
}

static int m5_suback_reason_code(int rc)
{
	switch (rc) {
	case M5_RC_GRANTED_QOS0:
	case M5_RC_GRANTED_QOS1:
	case M5_RC_GRANTED_QOS2:
	case M5_RC_UNSPECIFIED_ERROR:
	case M5_RC_IMPLEMENTATION_SPECIFIC_ERROR:
	case M5_RC_NOT_AUTHORIZED:
	case M5_RC_TOPIC_FILTER_INVALID:
	case M5_RC_PACKET_IDENTIFIER_IN_USE:
	case M5_RC_QUOTA_EXCEEDED:
	case M5_RC_SHARED_SUBSCRIPTION_NOT_SUPPORTED:
	case M5_RC_SUBSCRIPTION_IDENTIFIERS_NOT_SUPPORTED:
	case M5_RC_WILDCARD_SUBSCRIPTION_NOT_SUPPORTED:
		return M5_SUCCESS;
	}

	return M5_INVALID_ARGUMENT;
}

static int m5_suback_reason_codes(uint8_t *rcodes, uint8_t elements)
{
	uint8_t i = 0;

	while (i < elements) {
		int rc;

		rc = m5_suback_reason_code(rcodes[i]);
		if (rc != M5_SUCCESS) {
			return rc;
		}

		i++;
	};

	return M5_SUCCESS;
}

static int m5_pack_suback_payload(struct app_buf *buf, struct m5_suback *msg)
{
	int rc;

	rc = m5_suback_reason_codes(msg->rc, msg->rc_items);
	if (rc != M5_SUCCESS) {
		return rc;
	}

	memcpy(buf->data + buf->len, msg->rc, msg->rc_items);
	buf->len += msg->rc_items;

	return M5_SUCCESS;
}

static int m5_pack_suback_unsuback(struct m5_ctx *ctx, struct app_buf *buf,
				   struct m5_suback *msg, struct m5_prop *prop,
				   enum m5_pkt_type type);

int m5_pack_suback(struct m5_ctx *ctx, struct app_buf *buf,
		   struct m5_suback *msg, struct m5_prop *prop)
{
	return m5_pack_suback_unsuback(ctx, buf, msg, prop, M5_PKT_SUBACK);
}

static int m5_unpack_suback_payload(struct app_buf *buf, struct m5_suback *msg,
				    uint8_t elements)
{
	int rc;

	if (APPBUF_FREE_READ_SPACE(buf) < elements || msg->rc_size < elements) {
		return M5_NOT_ENOUGH_SPACE_IN_BUFFER;
	}

	rc = m5_suback_reason_codes(buf->data + buf->offset, elements);
	if (rc != M5_SUCCESS) {
		return rc;
	}

	memcpy(msg->rc, buf->data + buf->offset, elements);
	buf->offset += elements;
	msg->rc_items = elements;

	return M5_SUCCESS;
}

static int m5_unpack_suback_unsuback(struct m5_ctx *ctx,
				     struct app_buf *buf,
				     struct m5_suback *msg,
				     struct m5_prop *prop,
				     enum m5_pkt_type type);

int m5_unpack_suback(struct m5_ctx *ctx, struct app_buf *buf,
		     struct m5_suback *msg, struct m5_prop *prop)
{
	return m5_unpack_suback_unsuback(ctx, buf, msg, prop, M5_PKT_SUBACK);
}

static int m5_pack_topics(struct app_buf *buf, struct m5_topics *topics)
{
	uint8_t i;

	for (i = 0; i < topics->items; i++) {
		m5_add_binary(buf, topics->topics[i], topics->len[i]);
	}

	return M5_SUCCESS;
}

static int m5_unpack_topics(struct app_buf *buf, struct m5_topics *topics,
			    uint32_t payload_wsize)
{
	uint32_t read_bytes = buf->offset;
	uint8_t i = 0;
	int rc;

	do {
		if (i >= topics->size) {
			return M5_NOT_ENOUGH_SPACE_IN_BUFFER;
		}

		rc = m5_unpack_binary(buf, &topics->topics[i], &topics->len[i]);
		if (rc != M5_SUCCESS) {
			return rc;
		}

		i++;
	} while (APPBUF_FREE_READ_SPACE(buf) > 0);

	topics->items = i;

	read_bytes = buf->offset - read_bytes;
	if (read_bytes != payload_wsize) {
		return M5_INVALID_ARGUMENT;
	}

	return M5_SUCCESS;
}

int m5_pack_unsuback(struct m5_ctx *ctx, struct app_buf *buf,
		     struct m5_suback *msg, struct m5_prop *prop)
{
	return m5_pack_suback_unsuback(ctx, buf, msg, prop, M5_PKT_UNSUBACK);
}

int m5_unpack_unsuback(struct m5_ctx *ctx, struct app_buf *buf,
		       struct m5_suback *msg, struct m5_prop *prop)
{
	return m5_unpack_suback_unsuback(ctx, buf, msg, prop, M5_PKT_UNSUBACK);
}

static int m5_pack_ping_msgs(struct m5_ctx *ctx, struct app_buf *buf,
			     enum m5_pkt_type pkt_type)
{
	int rc;

	if (buf == NULL || APPBUF_FREE_WRITE_SPACE(buf) < 2) {
		rc = M5_NOT_ENOUGH_SPACE_IN_BUFFER;
		goto lb_exit;
	}

	buf->data[buf->len + 0] = (pkt_type << 4);
	buf->data[buf->len + 1] = 0;
	buf->len += 2;

	rc = M5_SUCCESS;
lb_exit:
	m5_ctx_status(ctx, rc);

	return rc;
}

int m5_pack_pingreq(struct m5_ctx *ctx, struct app_buf *buf)
{
	return m5_pack_ping_msgs(ctx, buf, M5_PKT_PINGREQ);
}

int m5_pack_pingresp(struct m5_ctx *ctx, struct app_buf *buf)
{
	return m5_pack_ping_msgs(ctx, buf, M5_PKT_PINGRESP);
}

static int m5_unpack_ping_msgs(struct m5_ctx *ctx, struct app_buf *buf,
			       enum m5_pkt_type pkt_type)
{
	int rc;

	if (buf == NULL || APPBUF_FREE_READ_SPACE(buf) < 2) {
		rc = M5_NOT_ENOUGH_SPACE_IN_BUFFER;
		goto lb_exit;
	}

	if (buf->data[buf->offset + 0] != (pkt_type << 4) ||
	    buf->data[buf->offset + 1] != 0) {
		rc = M5_INVALID_FIXED_HEADER;
		goto lb_exit;
	}

	buf->offset += 2;

	rc = M5_SUCCESS;
lb_exit:
	m5_ctx_status(ctx, rc);

	return rc;
}

int m5_unpack_pingreq(struct m5_ctx *ctx, struct app_buf *buf)
{
	return m5_unpack_ping_msgs(ctx, buf, M5_PKT_PINGREQ);
}

int m5_unpack_pingresp(struct m5_ctx *ctx, struct app_buf *buf)
{
	return m5_unpack_ping_msgs(ctx, buf, M5_PKT_PINGRESP);
}

static int m5_pack_disconnect_auth(struct m5_ctx *ctx, struct app_buf *buf,
				   uint8_t reason_code, struct m5_prop *prop,
				   enum m5_pkt_type type);

int m5_pack_disconnect(struct m5_ctx *ctx, struct app_buf *buf,
		       uint8_t reason_code, struct m5_prop *prop)
{
	return m5_pack_disconnect_auth(ctx, buf, reason_code, prop,
				       M5_PKT_DISCONNECT);
}

static int m5_unpack_disconnect_auth(struct m5_ctx *ctx, struct app_buf *buf,
				     uint8_t *reason_code, struct m5_prop *prop,
				     enum m5_pkt_type type);

int m5_unpack_disconnect(struct m5_ctx *ctx, struct app_buf *buf,
			 uint8_t *reason_code, struct m5_prop *prop)
{
	return m5_unpack_disconnect_auth(ctx, buf, reason_code, prop,
					 M5_PKT_DISCONNECT);
}

int m5_pack_auth(struct m5_ctx *ctx, struct app_buf *buf, uint8_t reason_code,
		 struct m5_prop *prop)
{
	return m5_pack_disconnect_auth(ctx, buf, reason_code,
				       prop, M5_PKT_AUTH);
}

int m5_unpack_auth(struct m5_ctx *ctx, struct app_buf *buf,
		   uint8_t *reason_code, struct m5_prop *prop)
{
	return m5_unpack_disconnect_auth(ctx, buf, reason_code,
					 prop, M5_PKT_AUTH);
}

struct pack_info {
	int (*fixed_hdr)(struct app_buf *, struct pack_info *, void *data);
	int (*var_hdr)(struct app_buf *, struct pack_info *, void *data,
		       struct m5_prop *);
	int (*payload)(struct app_buf *, struct pack_info *, void *data);

	uint32_t var_hdr_size;
	uint32_t payload_size;
	uint32_t prop_wsize;

	uint8_t fixed_hdr_reserved;
	enum m5_pkt_type pkt_type;
	uint8_t has_properties;
	uint32_t remlen;
};

static int pack_fixed_hdr(struct app_buf *buf,
			  struct pack_info *pack_info,
			  void *data)
{
	uint8_t reserved = pack_info->fixed_hdr_reserved;
	uint8_t type = pack_info->pkt_type;

	ARG_UNUSED(data);

	m5_add_u8(buf, ((uint8_t)type << 4) | (reserved & 0x0F));

	return M5_SUCCESS;
}

static int pack(struct m5_ctx *ctx,
		struct app_buf *buf,
		struct pack_info *pack_info,
		void *msg,
		struct m5_prop *prop)
{
	uint32_t prop_wsize_wsize;
	uint32_t full_msg_size;
	uint32_t prop_wsize;
	uint32_t rlen_wsize;
	uint32_t rlen;
	int rc;

	if (buf == NULL) {
		rc = M5_INVALID_NULL_ARGUMENT;
		goto lb_exit;
	}

	if (pack_info->has_properties != 0) {
		rc = m5_prop_wsize(pack_info->pkt_type, prop, &prop_wsize);
		if (rc != M5_SUCCESS) {
			rc = M5_INVALID_PROPERTIES;
			goto lb_exit;
		}

		rc = m5_rlen_wsize(prop_wsize, &prop_wsize_wsize);
		if (rc != M5_SUCCESS) {
			rc = M5_INVALID_PROPERTY_VBI;
			goto lb_exit;
		}

		pack_info->prop_wsize = prop_wsize;
	}

	rlen = pack_info->var_hdr_size + pack_info->payload_size;
	if (pack_info->has_properties != 0) {
		rlen += prop_wsize_wsize + prop_wsize;
	}

	pack_info->remlen = rlen;

	rc = m5_rlen_wsize(rlen, &rlen_wsize);
	if (rc != M5_SUCCESS) {
		rc = M5_INVALID_REMLEN_VBI;
		goto lb_exit;
	}

	full_msg_size = M5_PACKET_TYPE_WSIZE + rlen + rlen_wsize;
	if (APPBUF_FREE_WRITE_SPACE(buf) < full_msg_size) {
		rc = M5_NOT_ENOUGH_SPACE_IN_BUFFER;
		goto lb_exit;
	}

	rc = pack_info->fixed_hdr(buf, pack_info, msg);
	if (rc != M5_SUCCESS) {
		rc = M5_INVALID_FIXED_HEADER;
		goto lb_exit;
	}

	m5_encode_int(buf, rlen);

	if (pack_info->var_hdr != NULL) {
		rc = pack_info->var_hdr(buf, pack_info, msg, prop);
		if (rc != M5_SUCCESS) {
			rc = M5_INVALID_VARIABLE_HEADER;
			goto lb_exit;
		}
	}

	if (pack_info->payload != NULL) {
		rc = pack_info->payload(buf, pack_info, msg);
		if (rc != M5_SUCCESS) {
			rc = M5_INVALID_PAYLOAD;
			goto lb_exit;
		}
	}

	rc = M5_SUCCESS;
lb_exit:
	m5_ctx_status(ctx, rc);

	return rc;
}

static int pack_connect_var_hdr(struct app_buf *buf,
				struct pack_info *pack_info,
				void *data,
				struct m5_prop *prop)
{
	struct m5_connect *msg = (struct m5_connect *)data;
	uint8_t flags;
	int rc;

	m5_connect_compute_flags(msg, &flags);
	m5_str_add(buf, M5_PROTO_STR);
	m5_add_u8(buf, M5_PROTO_VERSION5);
	m5_add_u8(buf, flags);
	m5_add_u16(buf, msg->keep_alive);

	rc = m5_pack_prop(buf, prop, pack_info->prop_wsize);
	if (rc != M5_SUCCESS) {
		return rc;
	}

	return M5_SUCCESS;
}

static int pack_connect_payload(struct app_buf *buf,
				struct pack_info *pack_info,
				void *data)
{
	struct m5_connect *msg = (struct m5_connect *)data;

	ARG_UNUSED(pack_info);

	return m5_pack_connect_payload(buf, msg);
}

int m5_pack_connect(struct m5_ctx *ctx, struct app_buf *buf,
		    struct m5_connect *msg, struct m5_prop *prop)
{
	struct pack_info pack_info = {
		.pkt_type = M5_PKT_CONNECT,
		.fixed_hdr_reserved = 0x00,
		.has_properties = 1,
		.var_hdr_size = 10,
		.payload_size = 0,
		.fixed_hdr = pack_fixed_hdr,
		.var_hdr = pack_connect_var_hdr,
		.payload = pack_connect_payload,
	};
	int rc;

	rc = m5_connect_payload_wsize(msg, &pack_info.payload_size);
	if (rc != M5_SUCCESS) {
		return rc;
	}

	return pack(ctx, buf, &pack_info, msg, prop);
}

static int pack_connack_var_hdr(struct app_buf *buf,
				struct pack_info *pack_info,
				void *data,
				struct m5_prop *prop)
{
	struct m5_connack *msg = (struct m5_connack *)data;

	m5_add_u8(buf, msg->session_present > 0 ? 0x01 : 0x00);
	m5_add_u8(buf, msg->return_code);

	return m5_pack_prop(buf, prop, pack_info->prop_wsize);
}

int m5_pack_connack(struct m5_ctx *ctx, struct app_buf *buf,
		    struct m5_connack *msg, struct m5_prop *prop)
{
	struct pack_info pack_info = {
		.pkt_type = M5_PKT_CONNACK,
		.fixed_hdr_reserved = 0x00,
		.has_properties = 1,
		.var_hdr_size = 2,
		.payload_size = 0,
		.fixed_hdr = pack_fixed_hdr,
		.var_hdr = pack_connack_var_hdr,
		.payload = NULL,
	};

	return pack(ctx, buf, &pack_info, msg, prop);
}

static int pack_publish_var_hdr(struct app_buf *buf,
				struct pack_info *pack_info,
				void *data,
				struct m5_prop *prop)
{
	struct m5_publish *msg = (struct m5_publish *)data;

	m5_add_binary(buf, msg->topic_name, msg->topic_name_len);
	if (msg->qos != M5_QoS0) {
		m5_add_u16(buf, msg->packet_id);
	}

	return m5_pack_prop(buf, prop, pack_info->prop_wsize);
}

static int pack_publish_payload(struct app_buf *buf,
				struct pack_info *pack_info,
				void *data)
{
	struct m5_publish *msg = (struct m5_publish *)data;

	ARG_UNUSED(pack_info);

	if (msg->payload_len == 0) {
		return M5_SUCCESS;
	}

	return m5_pack_raw_binary(buf, msg->payload, msg->payload_len);
}

int m5_pack_publish(struct m5_ctx *ctx, struct app_buf *buf,
		    struct m5_publish *msg, struct m5_prop *prop)
{
	struct pack_info pack_info = {
		.pkt_type = M5_PKT_PUBLISH,
		.has_properties = 1,
		.payload_size = msg->payload_len,
		.fixed_hdr = pack_fixed_hdr,
		.var_hdr = pack_publish_var_hdr,
		.payload = pack_publish_payload,
	};
	int rc;

	rc = m5_publish_flags(msg, &pack_info.fixed_hdr_reserved);
	if (rc != M5_SUCCESS) {
		return rc;
	}

	pack_info.var_hdr_size = str_wsize(msg->topic_name_len);
	if (msg->qos != M5_QoS0) {
		if (msg->packet_id == 0) {
			return M5_INVALID_ARGUMENT;
		}

		pack_info.var_hdr_size += M5_PACKET_ID_WSIZE;
	}

	return pack(ctx, buf, &pack_info, msg, prop);
}

static int pack_pub_msgs_var_hdr(struct app_buf *buf,
				 struct pack_info *pack_info,
				 void *data,
				 struct m5_prop *prop)
{
	struct m5_pub_response *msg = (struct m5_pub_response *)data;

	m5_add_u16(buf, msg->packet_id);
	m5_add_u8(buf, msg->reason_code);

	return m5_pack_prop(buf, prop, pack_info->prop_wsize);
}

static int m5_pack_pub_msgs(struct m5_ctx *ctx,
			    struct app_buf *buf,
			    struct m5_pub_response *msg,
			    struct m5_prop *prop,
			    enum m5_pkt_type pkt_type)
{
	struct pack_info pack_info = {
		.pkt_type = pkt_type,
		.has_properties = 1,
		.var_hdr_size = 3,
		.payload_size = 0,
		.fixed_hdr = pack_fixed_hdr,
		.var_hdr = pack_pub_msgs_var_hdr,
		.payload = NULL,
	};
	int rc;

	if (msg->packet_id == 0) {
		return M5_INVALID_ARGUMENT;
	}

	rc = m5_pub_reason_code(pkt_type, msg->reason_code);
	if (rc != M5_SUCCESS) {
		return rc;
	}

	pack_info.fixed_hdr_reserved =
				(pkt_type == M5_PKT_PUBREL ? 0x02 : 0x00);

	return pack(ctx, buf, &pack_info, msg, prop);
}

static int pack_subscribe_var_hdr(struct app_buf *buf,
				  struct pack_info *pack_info,
				  void *data,
				  struct m5_prop *prop)
{
	struct m5_subscribe *msg = (struct m5_subscribe *)data;

	m5_add_u16(buf, msg->packet_id);

	return m5_pack_prop(buf, prop, pack_info->prop_wsize);
}

static int pack_subscribe_payload(struct app_buf *buf,
				  struct pack_info *pack_info,
				  void *data)
{
	struct m5_subscribe *msg = (struct m5_subscribe *)data;

	ARG_UNUSED(pack_info);

	return m5_pack_subscribe_payload(buf, msg);
}

int m5_pack_subscribe(struct m5_ctx *ctx, struct app_buf *buf,
		      struct m5_subscribe *msg, struct m5_prop *prop)
{
	struct pack_info pack_info = {
		.pkt_type = M5_PKT_SUBSCRIBE,
		.fixed_hdr_reserved = 0x02,
		.has_properties = 1,
		.var_hdr_size = 2,
		.fixed_hdr = pack_fixed_hdr,
		.var_hdr = pack_subscribe_var_hdr,
		.payload = pack_subscribe_payload,
	};
	int rc;

	if (msg->packet_id == 0) {
		return M5_INVALID_ARGUMENT;
	}

	rc = m5_topics_wsize(&msg->topics, &pack_info.payload_size);
	if (rc != M5_SUCCESS) {
		return rc;
	}

	/* add the options */
	pack_info.payload_size += msg->topics.items;

	return pack(ctx, buf, &pack_info, msg, prop);
}

static int pack_suback_unsuback_var_hdr(struct app_buf *buf,
					struct pack_info *pack_info,
					void *data,
					struct m5_prop *prop)
{
	struct m5_suback *msg = (struct m5_suback *)data;

	m5_add_u16(buf, msg->packet_id);

	return m5_pack_prop(buf, prop, pack_info->prop_wsize);
}

static int pack_suback_unsuback_payload(struct app_buf *buf,
					struct pack_info *pack_info,
					void *data)
{
	struct m5_suback *msg = (struct m5_suback *)data;

	ARG_UNUSED(pack_info);

	return m5_pack_suback_payload(buf, msg);
}

static int m5_pack_suback_unsuback(struct m5_ctx *ctx, struct app_buf *buf,
				   struct m5_suback *msg, struct m5_prop *prop,
				   enum m5_pkt_type type)
{
	struct pack_info pack_info = {
		.pkt_type = type,
		.fixed_hdr_reserved = 0x00,
		.has_properties = 1,
		.var_hdr_size = 2,
		.payload_size = msg->rc_items,
		.fixed_hdr = pack_fixed_hdr,
		.var_hdr = pack_suback_unsuback_var_hdr,
		.payload = pack_suback_unsuback_payload,
	};

	if (msg->packet_id == 0 || msg->rc_items == 0) {
		return M5_INVALID_ARGUMENT;
	}

	return pack(ctx, buf, &pack_info, msg, prop);
}

static int pack_unsubscribe_var_hdr(struct app_buf *buf,
				    struct pack_info *pack_info,
				    void *data,
				    struct m5_prop *prop)
{
	struct m5_unsubscribe *msg = (struct m5_unsubscribe *)data;

	ARG_UNUSED(pack_info);
	ARG_UNUSED(prop);

	m5_add_u16(buf, msg->packet_id);

	return M5_SUCCESS;
}

static int pack_unsubscribe_payload(struct app_buf *buf,
				    struct pack_info *pack_info, void *data)
{
	struct m5_unsubscribe *msg = (struct m5_unsubscribe *)data;

	ARG_UNUSED(pack_info);

	return m5_pack_topics(buf, &msg->topics);
}

int m5_pack_unsubscribe(struct m5_ctx *ctx, struct app_buf *buf,
			struct m5_unsubscribe *msg)
{
	struct pack_info pack_info = {
		.pkt_type = M5_PKT_UNSUBSCRIBE,
		.fixed_hdr_reserved = 0x02,
		.has_properties = 0,
		.var_hdr_size = 2,
		.fixed_hdr = pack_fixed_hdr,
		.var_hdr = pack_unsubscribe_var_hdr,
		.payload = pack_unsubscribe_payload,
	};
	int rc;

	if (msg->packet_id == 0x00 || msg->topics.items == 0) {
		return M5_INVALID_ARGUMENT;
	}

	rc = m5_topics_wsize(&msg->topics, &pack_info.payload_size);
	if (rc != M5_SUCCESS) {
		return rc;
	}

	return pack(ctx, buf, &pack_info, msg, NULL);
}

static int pack_disconnect_auth_var_hdr(struct app_buf *buf,
					struct pack_info *pack_info,
					void *data,
					struct m5_prop *prop)
{
	uint8_t reason_code = *(uint8_t *)data;
	int rc;

	if (pack_info->remlen > 0) {
		m5_add_u8(buf, reason_code);

		if (pack_info->remlen > 1) {
			rc = m5_pack_prop(buf, prop, pack_info->prop_wsize);
			if (rc != M5_SUCCESS) {
				return rc;
			}
		}
	}

	return M5_SUCCESS;
}

static int m5_pack_disconnect_auth(struct m5_ctx *ctx,
				   struct app_buf *buf,
				   uint8_t reason_code,
				   struct m5_prop *prop,
				   enum m5_pkt_type type)
{
	struct pack_info pack_info = {
		.pkt_type = type,
		.fixed_hdr_reserved = 0x00,
		.has_properties = 1,
		.var_hdr_size = 1,
		.fixed_hdr = pack_fixed_hdr,
		.var_hdr = pack_disconnect_auth_var_hdr,
		.payload = NULL,
	};

	if (prop == NULL && reason_code == 0) {
		pack_info.has_properties = 0;
		pack_info.var_hdr_size = 0;
	}

	return pack(ctx, buf, &pack_info, &reason_code, prop);
}

static int unpack(struct m5_ctx *ctx,
		  struct app_buf *buf,
		  struct pack_info *pack_info,
		  void *msg,
		  struct m5_prop *prop)
{
	uint32_t full_packet_size;
	uint32_t already_read;
	uint32_t rlen_wsize;
	uint32_t rlen;
	int rc;

	if (buf == NULL || msg == NULL) {
		rc = M5_INVALID_NULL_ARGUMENT;
		goto lb_exit;
	}

	already_read = buf->offset;

	rc = pack_info->fixed_hdr(buf, pack_info, msg);
	if (rc != M5_SUCCESS) {
		rc = M5_INVALID_FIXED_HEADER;
		goto lb_exit;
	}

	rc = m5_decode_int(buf, &rlen, &rlen_wsize);
	if (rc != M5_SUCCESS) {
		rc = M5_INVALID_REMLEN_VBI;
		goto lb_exit;
	}

	pack_info->remlen = rlen;

	if (APPBUF_FREE_READ_SPACE(buf) < rlen) {
		rc = M5_NOT_ENOUGH_SPACE_IN_BUFFER;
		goto lb_exit;
	}

	if (pack_info->var_hdr != NULL) {
		rc = pack_info->var_hdr(buf, pack_info, msg, prop);
		if (rc != M5_SUCCESS) {
			rc = M5_INVALID_VARIABLE_HEADER;
			goto lb_exit;
		}
	}

	full_packet_size = M5_PACKET_TYPE_WSIZE + rlen + rlen_wsize;

	if (pack_info->payload != NULL) {
		pack_info->payload_size = full_packet_size -
					  (buf->offset - already_read);
		rc = pack_info->payload(buf, pack_info, msg);
		if (rc != M5_SUCCESS) {
			rc = M5_INVALID_PAYLOAD;
			goto lb_exit;
		}
	}

	if (buf->offset - already_read != full_packet_size) {
		rc = M5_FINISHED_READING_INVALID_LENGTH;
		goto lb_exit;
	}

	rc = M5_SUCCESS;
lb_exit:
	m5_ctx_status(ctx, rc);

	return rc;
}

static int unpack_fixed_hdr(struct app_buf *buf,
			    struct pack_info *pack_info,
			    void *data)
{
	uint8_t first;
	int rc;

	ARG_UNUSED(data);

	rc = m5_unpack_u8(buf, &first);
	if (rc != M5_SUCCESS) {
		return rc;
	}

	if ((first >> 4) != pack_info->pkt_type ||
	    ((first & 0x0F) != (pack_info->fixed_hdr_reserved & 0x0F))) {
		return M5_INVALID_ARGUMENT;
	}

	return M5_SUCCESS;
}

static int unpack_connect_var_hdr(struct app_buf *buf,
				  struct pack_info *pack_info,
				  void *data,
				  struct m5_prop *prop)
{
	struct m5_connect *msg = (struct m5_connect *)data;
	int rc;

	ARG_UNUSED(pack_info);

	rc = m5_unpack_proto_name(buf);
	if (rc != M5_SUCCESS)	{
		return rc;
	}

	/* MQTT protocol version */
	rc = m5_unpack_proto_version(buf);
	if (rc != M5_SUCCESS) {
		return rc;
	}

	rc = m5_unpack_connect_flags(buf, msg);
	if (rc != M5_SUCCESS) {
		return rc;
	}

	rc = m5_unpack_connect_keep_alive(buf, msg);
	if (rc != M5_SUCCESS) {
		return rc;
	}

	rc = m5_unpack_prop(buf, prop, M5_PKT_CONNECT);
	if (rc != M5_SUCCESS) {
		return rc;
	}

	return M5_SUCCESS;
}

static int unpack_connect_payload(struct app_buf *buf,
				  struct pack_info *pack_info,
				  void *data)
{
	struct m5_connect *msg = (struct m5_connect *)data;

	ARG_UNUSED(pack_info);

	return m5_unpack_connect_payload(buf, msg);
}

int m5_unpack_connect(struct m5_ctx *ctx, struct app_buf *buf,
		      struct m5_connect *msg, struct m5_prop *prop)
{
	struct pack_info pack_info = {
		.fixed_hdr = unpack_fixed_hdr,
		.var_hdr = unpack_connect_var_hdr,
		.payload = unpack_connect_payload,

		.pkt_type = M5_PKT_CONNECT,
		.fixed_hdr_reserved = 0x00 };

	return unpack(ctx, buf, &pack_info, msg, prop);
}

static int unpack_connack_var_hdr(struct app_buf *buf,
				  struct pack_info *pack_info,
				  void *data,
				  struct m5_prop *prop)
{
	struct m5_connack *msg = (struct m5_connack *)data;
	int rc;

	ARG_UNUSED(pack_info);

	rc = m5_unpack_u8(buf, &msg->session_present);
	if (rc != M5_SUCCESS || msg->session_present > 0x01) {
		return M5_INVALID_ARGUMENT;
	}

	rc = m5_unpack_u8(buf, &msg->return_code);
	if (rc != M5_SUCCESS) {
		return rc;
	}

	rc = m5_unpack_prop(buf, prop, M5_PKT_CONNACK);
	if (rc != M5_SUCCESS) {
		return rc;
	}

	return M5_SUCCESS;
}

int m5_unpack_connack(struct m5_ctx *ctx, struct app_buf *buf,
		      struct m5_connack *msg, struct m5_prop *prop)
{
	struct pack_info pack_info = {
		.fixed_hdr = unpack_fixed_hdr,
		.var_hdr = unpack_connack_var_hdr,
		.payload = NULL,

		.pkt_type = M5_PKT_CONNACK,
		.fixed_hdr_reserved = 0x00 };

	return unpack(ctx, buf, &pack_info, msg, prop);
}

static int unpack_publish_fixed_hdr(struct app_buf *buf,
				    struct pack_info *pack_info,
				    void *data)
{
	struct m5_publish *msg = (struct m5_publish *)data;
	uint8_t first;
	int rc;

	ARG_UNUSED(pack_info);

	rc = m5_unpack_u8(buf, &first);
	if (rc != M5_SUCCESS || (first & 0xF0) != (M5_PKT_PUBLISH << 4)) {
		return M5_INVALID_ARGUMENT;
	}

	rc = m5_unpack_publish_flags(msg, first);
	if (rc != M5_SUCCESS) {
		return rc;
	}

	return M5_SUCCESS;
}

static int unpack_publish_var_hdr(struct app_buf *buf,
				  struct pack_info *pack_info,
				  void *data,
				  struct m5_prop *prop)
{
	struct m5_publish *msg = (struct m5_publish *)data;
	int rc;

	ARG_UNUSED(pack_info);

	rc = m5_buffer_set(&msg->topic_name, &msg->topic_name_len, buf);
	if (rc != M5_SUCCESS) {
		return rc;
	}

	if (msg->qos != M5_QoS0) {
		rc = m5_unpack_u16(buf, &msg->packet_id);
		if (rc != M5_SUCCESS) {
			return rc;
		}
	}

	rc = m5_unpack_prop(buf, prop, M5_PKT_PUBLISH);
	if (rc != M5_SUCCESS) {
		return rc;
	}

	return M5_SUCCESS;
}

static int unpack_publish_payload(struct app_buf *buf,
				  struct pack_info *pack_info,
				  void *data)
{
	struct m5_publish *msg = (struct m5_publish *)data;

	msg->payload_len = pack_info->payload_size;

	if (msg->payload_len > 0) {
		msg->payload = buf->data + buf->offset;
		buf->offset += msg->payload_len;
	} else {
		msg->payload = NULL;
	}

	return M5_SUCCESS;
}

int m5_unpack_publish(struct m5_ctx *ctx, struct app_buf *buf,
		      struct m5_publish *msg, struct m5_prop *prop)
{
	struct pack_info pack_info = {
		.fixed_hdr = unpack_publish_fixed_hdr,
		.var_hdr = unpack_publish_var_hdr,
		.payload = unpack_publish_payload,

		.fixed_hdr_reserved = 0x00 };

	return unpack(ctx, buf, &pack_info, msg, prop);
}

static int unpack_pub_msgs_var_hdr(struct app_buf *buf,
				   struct pack_info *pack_info,
				   void *data,
				   struct m5_prop *prop)
{
	struct m5_pub_response *msg = (struct m5_pub_response *)data;
	int rc;

	ARG_UNUSED(pack_info);

	rc = m5_unpack_u16(buf, &msg->packet_id);
	if (rc != M5_SUCCESS) {
		return rc;
	}

	rc = m5_unpack_u8(buf, &msg->reason_code);
	if (rc != M5_SUCCESS) {
		return rc;
	}

	rc = m5_unpack_prop(buf, prop, pack_info->pkt_type);
	if (rc != M5_SUCCESS) {
		return rc;
	}

	return M5_SUCCESS;
}

static int m5_unpack_pub_msgs(struct m5_ctx *ctx, struct app_buf *buf,
			      struct m5_pub_response *msg, struct m5_prop *prop,
			      enum m5_pkt_type pkt_type)
{
	struct pack_info pack_info = {
		.fixed_hdr = unpack_fixed_hdr,
		.var_hdr = unpack_pub_msgs_var_hdr,
		.payload = NULL };

	pack_info.pkt_type = pkt_type;
	pack_info.fixed_hdr_reserved =
				(pkt_type == M5_PKT_PUBREL ? 0x02 : 0x00);

	return unpack(ctx, buf, &pack_info, msg, prop);
}

static int unpack_subscribe_var_hdr(struct app_buf *buf,
				    struct pack_info *pack_info,
				    void *data,
				    struct m5_prop *prop)
{
	struct m5_subscribe *msg = (struct m5_subscribe *)data;
	int rc;

	ARG_UNUSED(pack_info);

	rc = m5_unpack_u16(buf, &msg->packet_id);
	if (rc != M5_SUCCESS || msg->packet_id == 0) {
		return M5_INVALID_ARGUMENT;
	}

	rc = m5_unpack_prop(buf, prop, M5_PKT_SUBSCRIBE);
	if (rc != M5_SUCCESS) {
		return rc;
	}

	return M5_SUCCESS;
}

static int unpack_subscribe_payload(struct app_buf *buf,
				    struct pack_info *pack_info,
				    void *data)
{
	struct m5_subscribe *msg = (struct m5_subscribe *)data;
	int rc;

	if (pack_info->payload_size == 0) {
		return M5_INVALID_ARGUMENT;
	}

	rc = m5_unpack_subscribe_payload(buf, msg, pack_info->payload_size);
	if (rc != M5_SUCCESS) {
		return rc;
	}

	return M5_SUCCESS;
}

int m5_unpack_subscribe(struct m5_ctx *ctx, struct app_buf *buf,
			struct m5_subscribe *msg, struct m5_prop *prop)
{
	struct pack_info pack_info = {
		.fixed_hdr = unpack_fixed_hdr,
		.var_hdr = unpack_subscribe_var_hdr,
		.payload = unpack_subscribe_payload,

		.pkt_type = M5_PKT_SUBSCRIBE,
		.fixed_hdr_reserved = 0x02 };

	return unpack(ctx, buf, &pack_info, msg, prop);
}

static int unpack_suback_unsuback_var_hdr(struct app_buf *buf,
					  struct pack_info *pack_info,
					  void *data,
					  struct m5_prop *prop)
{
	struct m5_suback *msg = (struct m5_suback *)data;
	int rc;

	ARG_UNUSED(pack_info);

	rc = m5_unpack_u16(buf, &msg->packet_id);
	if (rc != M5_SUCCESS || msg->packet_id == 0) {
		return M5_INVALID_ARGUMENT;
	}

	rc = m5_unpack_prop(buf, prop, pack_info->pkt_type);
	if (rc != M5_SUCCESS) {
		return rc;
	}

	return M5_SUCCESS;
}

static int unpack_suback_unsuback_payload(struct app_buf *buf,
					  struct pack_info *pack_info,
					  void *data)
{
	struct m5_suback *msg = (struct m5_suback *)data;
	int rc;

	if (pack_info->payload_size == 0) {
		return M5_INVALID_ARGUMENT;
	}

	rc = m5_unpack_suback_payload(buf, msg, pack_info->payload_size);
	if (rc != M5_SUCCESS) {
		return rc;
	}

	return M5_SUCCESS;
}

static int m5_unpack_suback_unsuback(struct m5_ctx *ctx,
				     struct app_buf *buf,
				     struct m5_suback *msg,
				     struct m5_prop *prop,
				     enum m5_pkt_type pkt_type)
{
	struct pack_info pack_info = {
		.fixed_hdr = unpack_fixed_hdr,
		.var_hdr = unpack_suback_unsuback_var_hdr,
		.payload = unpack_suback_unsuback_payload,

		.pkt_type = pkt_type,
		.fixed_hdr_reserved = 0x00 };

	return unpack(ctx, buf, &pack_info, msg, prop);
}

static int unpack_unsubscribe_var_hdr(struct app_buf *buf,
				      struct pack_info *pack_info,
				      void *data, struct m5_prop *prop)
{
	struct m5_unsubscribe *msg = (struct m5_unsubscribe *)data;
	int rc;

	ARG_UNUSED(pack_info);
	ARG_UNUSED(prop);

	rc = m5_unpack_u16(buf, &msg->packet_id);
	if (rc != M5_SUCCESS || msg->packet_id == 0) {
		return M5_INVALID_ARGUMENT;
	}

	return M5_SUCCESS;
}

static int unpack_unsubscribe_payload(struct app_buf *buf,
				      struct pack_info *pack_info,
				      void *data)
{
	struct m5_unsubscribe *msg = (struct m5_unsubscribe *)data;
	int rc;

	if (pack_info->payload_size == 0) {
		return M5_INVALID_ARGUMENT;
	}

	rc = m5_unpack_topics(buf, &msg->topics, pack_info->payload_size);
	if (rc != M5_SUCCESS) {
		return rc;
	}

	return M5_SUCCESS;
}

int m5_unpack_unsubscribe(struct m5_ctx *ctx, struct app_buf *buf,
			  struct m5_unsubscribe *msg)
{
	struct pack_info pack_info = {
		.fixed_hdr = unpack_fixed_hdr,
		.var_hdr = unpack_unsubscribe_var_hdr,
		.payload = unpack_unsubscribe_payload,

		.pkt_type = M5_PKT_UNSUBSCRIBE,
		.fixed_hdr_reserved = 0x02 };

	return unpack(ctx, buf, &pack_info, msg, NULL);
}

static int unpack_disconnect_auth_var_hdr(struct app_buf *buf,
					  struct pack_info *pack_info,
					  void *data, struct m5_prop *prop)
{
	uint8_t *reason_code = (uint8_t *)data;
	int rc;

	if (pack_info->remlen == 0) {
		*reason_code = 0x00;
		goto lb_exit_ok;
	}

	rc = m5_unpack_u8(buf, reason_code);
	if (rc != M5_SUCCESS) {
		rc = M5_INVALID_VARIABLE_HEADER;
		goto lb_exit;
	}

	if (pack_info->remlen > 1) {
		rc = m5_unpack_prop(buf, prop, pack_info->pkt_type);
		if (rc != M5_SUCCESS) {
			rc = M5_INVALID_PROPERTIES;
			goto lb_exit;
		}
	}

lb_exit_ok:
	rc = M5_SUCCESS;

lb_exit:
	return rc;
}

static int m5_unpack_disconnect_auth(struct m5_ctx *ctx, struct app_buf *buf,
				     uint8_t *reason_code, struct m5_prop *prop,
				     enum m5_pkt_type type)
{
	struct pack_info pack_info = {
		.fixed_hdr = unpack_fixed_hdr,
		.var_hdr = unpack_disconnect_auth_var_hdr,
		.payload = NULL,

		.pkt_type = type,
		.fixed_hdr_reserved = 0x00 };

	return unpack(ctx, buf, &pack_info, reason_code, prop);
}
