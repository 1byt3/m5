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

#include "m5.c"

#include <string.h>
#include <stdio.h>

#define TEST_HDR(msg)	printf("------------------------\n%s\n", (msg))
#define RC_TO_STR(rc)	((rc) == EXIT_SUCCESS ? "OK" : "ERROR")
#define DBG(msg)	printf("\t%s:%d %s\n", __func__, __LINE__, msg)


static const char * const m5_prop_name[] = {
	NULL,
	"PAYLOAD_FORMAT_INDICATOR",
	"REQUEST_PROBLEM_INFORMATION",
	"REQUEST_RESPONSE_INFORMATION",
	"MAXIMUM_QOS",
	"RETAIN_AVAILABLE",
	"WILDCARD_SUBSCRIPTION_AVAILABLE",
	"SUBSCRIPTION_IDENTIFIER_AVAILABLE",
	"SHARED_SUBSCRIPTION_AVAILABLE",
	"SERVER_KEEP_ALIVE",
	"RECEIVE_MAXIMUM",
	"TOPIC_ALIAS_MAXIMUM",
	"TOPIC_ALIAS",
	"PUBLICATION_EXPIRY_INTERVAL",
	"SESSION_EXPIRY_INTERVAL",
	"WILL_DELAY_INTERVAL",
	"MAXIMUM_PACKET_SIZE",
	"CONTENT_TYPE",
	"RESPONSE_TOPIC",
	"CORRELATION_DATA",
	"ASSIGNED_CLIENT_IDENTIFIER",
	"AUTH_METHOD",
	"AUTH_DATA",
	"RESPONSE_INFORMATION",
	"SERVER_REFERENCE",
	"REASON_STR",
	"SUBSCRIPTION_IDENTIFIER",
	"USER_PROPERTY",
};

void print_raw(uint8_t *data, size_t len)
{
	size_t i;

	for (i = 0; i < len; i++) {
		printf("%02x\t", data[i]);
		if (i > 0 && (i + 1) % 8 == 0) {
			printf("\n");
		}
	}

	printf("\n");
}

void print_buf(struct app_buf *buf)
{
	printf("Size: %zu, Len: %zu, Offset: %zu\n",
	       buf->size, buf->len, buf->offset);

	if (buf == NULL) {
		return;
	}

	print_raw(buf->data, buf->len);
}

static uint8_t data[256];

static int encode_decode(uint32_t val)
{
	struct app_buf buf = { 0 };
	uint32_t val_wsize;
	uint32_t v_wsize;
	uint32_t v;
	int rc;

	buf.data = data;
	buf.size = sizeof(data);

	rc = m5_encode_int(&buf, val);
	if (rc != EXIT_SUCCESS) {
		DBG("m5_encode_int");
		return rc;
	}

	rc = m5_rlen_wsize(val, &val_wsize);
	if (rc != EXIT_SUCCESS) {
		DBG("m5_rlen_wsize");
		return rc;
	}

	if (buf.len != val_wsize) {
		DBG("m5_encode_int: logic error");
		return rc;
	}

	rc = m5_decode_int(&buf, &v, &v_wsize);
	if (rc != EXIT_SUCCESS) {
		DBG("m5_rlen_wsize");
		return rc;
	}

	if (v != val || v_wsize != val_wsize) {
		DBG("m5_encode_int/m5_decode_int: logic error");
		return rc;
	}

	return EXIT_SUCCESS;
}

static void test_int_encoding(void)
{
	int rc;

	TEST_HDR(__func__);

	rc = encode_decode(127);
	if (rc != EXIT_SUCCESS) {
		exit(rc);
	}

	rc = encode_decode(16383);
	if (rc != EXIT_SUCCESS) {
		exit(rc);
	}

	rc = encode_decode(2097151);
	if (rc != EXIT_SUCCESS) {
		exit(rc);
	}

	rc = encode_decode(268435455);
	if (rc != EXIT_SUCCESS) {
		exit(rc);
	}

	/* must fail */
	rc = encode_decode(268435455 + 1);
	if (rc == EXIT_SUCCESS) {
		exit(rc);
	}
	rc = EXIT_SUCCESS;

	printf("%s\n", RC_TO_STR(rc));
}

static void test_m5_add_u16(void)
{
	struct app_buf buf = { .data = data, .len = 0, .offset = 0,
			       .size = sizeof(data)};

	TEST_HDR(__func__);

	m5_add_u16(&buf, 0xABCD);
	if (buf.data[0] != 0xAB || buf.data[1] != 0xCD) {
		exit(1);
	}

	if (buf.len != 2) {
		exit(1);
	}
}

static void test_m5_add_str(void)
{
	struct app_buf buf = { .data = data, .len = 0, .offset = 0,
			       .size = sizeof(data)};
	const char *str = "Hello, World!";

	TEST_HDR(__func__);

	m5_str_add(&buf, str);

	if (m5_u16(buf.data) != strlen(str)) {
		exit(1);
	}

	if (memcmp(buf.data + 2, str, strlen(str)) != 0) {
		exit(1);
	}
}

#define DEBUG_PROP_FLAGS(prop, new_prop)			\
	printf("Prev prop flags: 0x%08x, adding: %s\n",		\
	       prop.flags, m5_prop_name[(new_prop)])

void test_m5_connect(void)
{
	struct app_buf buf = { .data = data, .len = 0, .offset = 0,
			       .size = sizeof(data)};
	char *will_msg = "will msg payload";
	char *client_id = "m5_client";
	char *will_topic = "sensors";
	struct m5_connect msg = { 0 };
	struct m5_prop prop = { 0 };
	int rc;
	int i;

	TEST_HDR(__func__);

	memset(data, 0, sizeof(data));

	DEBUG_PROP_FLAGS(prop, REMAP_SESSION_EXPIRY_INTERVAL);
	m5_prop_session_expiry_interval(&prop, 1);
	DEBUG_PROP_FLAGS(prop, REMAP_WILL_DELAY_INTERVAL);
	m5_prop_will_delay_interval(&prop, 1);
	DEBUG_PROP_FLAGS(prop, REMAP_RECEIVE_MAXIMUM);
	m5_prop_receive_max(&prop, 5);
	DEBUG_PROP_FLAGS(prop, REMAP_MAXIMUM_PACKET_SIZE);
	m5_prop_max_packet_size(&prop, 5);
	DEBUG_PROP_FLAGS(prop, REMAP_TOPIC_ALIAS_MAXIMUM);
	m5_prop_topic_alias_max(&prop, 1);
	DEBUG_PROP_FLAGS(prop, REMAP_REQUEST_RESPONSE_INFORMATION);
	m5_prop_request_response_info(&prop, 1);
	DEBUG_PROP_FLAGS(prop, REMAP_REQUEST_PROBLEM_INFORMATION);
	m5_prop_request_problem_info(&prop, 1);
	DEBUG_PROP_FLAGS(prop, REMAP_USER_PROPERTY);
	for (i = 0; i < M5_USER_PROP_SIZE; i++) {
		rc = m5_prop_add_user_prop(&prop, (uint8_t *)"hello", 5,
						  (uint8_t *)"world!", 6);
		if (rc != EXIT_SUCCESS) {
			DBG("m5_prop_add_user_prop");
			exit(1);
		}
	}
	DEBUG_PROP_FLAGS(prop, REMAP_AUTH_METHOD);
	m5_prop_auth_method(&prop, (uint8_t *)"none", 4);
	DEBUG_PROP_FLAGS(prop, REMAP_AUTH_DATA);
	m5_prop_auth_data(&prop, (uint8_t *)"xxx", 3);

	msg.client_id = (uint8_t *)client_id;
	msg.client_id_len = strlen(client_id);
	msg.keep_alive = 0x0123;

	msg.will_topic = (uint8_t *)will_topic;
	msg.will_topic_len = strlen(will_topic);

	msg.will_msg = (uint8_t *)will_msg;
	msg.will_msg_len = strlen(will_msg);

	rc = m5_pack_connect(&buf, &msg, &prop);
	if (rc != EXIT_SUCCESS) {
		DBG("m5_pack_connect");
		exit(1);
	}

	printf("CONNECT\n");
	print_buf(&buf);
}

int main(void)
{
	test_int_encoding();
	test_m5_add_u16();
	test_m5_add_str();
	test_m5_connect();

	return 0;
}
