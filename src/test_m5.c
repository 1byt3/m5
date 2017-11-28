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
#define RC_TO_STR(rc)	((rc) == M5_SUCCESS ? "OK" : "ERROR")
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

static void print_raw(uint8_t *data, size_t len)
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

static void print_buf(struct app_buf *buf)
{
	printf("Size: %zu, Len: %zu, Offset: %zu\n",
	       buf->size, buf->len, buf->offset);

	if (buf == NULL) {
		return;
	}

	print_raw(buf->data, buf->len);
}

static uint8_t data[256];
static struct m5_ctx ctx;

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
	if (rc != M5_SUCCESS) {
		DBG("m5_encode_int");
		return rc;
	}

	rc = m5_rlen_wsize(val, &val_wsize);
	if (rc != M5_SUCCESS) {
		DBG("m5_rlen_wsize");
		return rc;
	}

	if (buf.len != val_wsize) {
		DBG("m5_encode_int: logic error");
		return rc;
	}

	rc = m5_decode_int(&buf, &v, &v_wsize);
	if (rc != M5_SUCCESS) {
		DBG("m5_rlen_wsize");
		return rc;
	}

	if (v != val || v_wsize != val_wsize) {
		DBG("m5_encode_int/m5_decode_int: logic error");
		return rc;
	}

	return M5_SUCCESS;
}

static void test_int_encoding(void)
{
	int rc;

	TEST_HDR(__func__);

	rc = encode_decode(127);
	if (rc != M5_SUCCESS) {
		exit(rc);
	}

	rc = encode_decode(16383);
	if (rc != M5_SUCCESS) {
		exit(rc);
	}

	rc = encode_decode(2097151);
	if (rc != M5_SUCCESS) {
		exit(rc);
	}

	rc = encode_decode(268435455);
	if (rc != M5_SUCCESS) {
		exit(rc);
	}

	/* must fail */
	DBG("The next test must fail");
	rc = encode_decode(268435455 + 1);
	if (rc == M5_SUCCESS) {
		exit(rc);
	}
	rc = M5_SUCCESS;

	printf("%s\n", RC_TO_STR(rc));
}

static void test_m5_add_u16(void)
{
	struct app_buf buf = { .data = data, .len = 0, .offset = 0,
			       .size = sizeof(data) };

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
			       .size = sizeof(data) };
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

#define PROP_CMP_STR(p1, p2, name)				\
	cmp_str(p1->_ ## name, p1->_ ## name ## _len,		\
		p2->_ ## name, p2->_ ## name ## _len)

#define PROP_CMP_INT(p1, p2, name)				\
	(p1->_ ## name == p2->_ ## name ? M5_SUCCESS : M5_INVALID_ARGUMENT)

static int cmp_str(uint8_t *a, uint16_t a_len, uint8_t *b, uint16_t b_len)
{
	if (a_len != b_len) {
		return M5_INVALID_ARGUMENT;
	}

	if (memcmp(a, b, a_len) != 0) {
		return M5_INVALID_ARGUMENT;
	}

	return M5_SUCCESS;
}

static int cmp_prop(struct m5_prop *p1, struct m5_prop *p2)
{
	int rc;

	rc = PROP_CMP_STR(p1, p2, auth_method);
	if (rc != M5_SUCCESS) {
		printf("[%s:%d]\n", __FILE__, __LINE__);
		return rc;
	}

	rc = PROP_CMP_STR(p1, p2, auth_data);
	if (rc != M5_SUCCESS) {
		printf("[%s:%d]\n", __FILE__, __LINE__);
		return rc;
	}

	rc = PROP_CMP_STR(p1, p2, content_type);
	if (rc != M5_SUCCESS) {
		printf("[%s:%d]\n", __FILE__, __LINE__);
		return rc;
	}

	rc = PROP_CMP_STR(p1, p2, correlation_data);
	if (rc != M5_SUCCESS) {
		printf("[%s:%d]\n", __FILE__, __LINE__);
		return rc;
	}

	rc = PROP_CMP_STR(p1, p2, response_info);
	if (rc != M5_SUCCESS) {
		printf("[%s:%d]\n", __FILE__, __LINE__);
		return rc;
	}

	rc = PROP_CMP_STR(p1, p2, server_reference);
	if (rc != M5_SUCCESS) {
		printf("[%s:%d]\n", __FILE__, __LINE__);
		return rc;
	}

	rc = PROP_CMP_STR(p1, p2, assigned_client_id);
	if (rc != M5_SUCCESS) {
		printf("[%s:%d]\n", __FILE__, __LINE__);
		return rc;
	}

	rc = PROP_CMP_STR(p1, p2, response_topic);
	if (rc != M5_SUCCESS) {
		printf("[%s:%d]\n", __FILE__, __LINE__);
		return rc;
	}

	rc = PROP_CMP_INT(p1, p2, max_packet_size);
	if (rc != M5_SUCCESS) {
		printf("[%s:%d]\n", __FILE__, __LINE__);
		return rc;
	}

	rc = PROP_CMP_INT(p1, p2, publication_expiry_interval);
	if (rc != M5_SUCCESS) {
		printf("[%s:%d]\n", __FILE__, __LINE__);
		return rc;
	}

	rc = PROP_CMP_INT(p1, p2, session_expiry_interval);
	if (rc != M5_SUCCESS) {
		printf("[%s:%d]\n", __FILE__, __LINE__);
		return rc;
	}

	rc = PROP_CMP_INT(p1, p2, subscription_id);
	if (rc != M5_SUCCESS) {
		printf("[%s:%d]\n", __FILE__, __LINE__);
		return rc;
	}

	rc = PROP_CMP_INT(p1, p2, will_delay_interval);
	if (rc != M5_SUCCESS) {
		printf("[%s:%d]\n", __FILE__, __LINE__);
		return rc;
	}

	rc = PROP_CMP_INT(p1, p2, receive_max);
	if (rc != M5_SUCCESS) {
		printf("[%s:%d]\n", __FILE__, __LINE__);
		return rc;
	}

	rc = PROP_CMP_INT(p1, p2, server_keep_alive);
	if (rc != M5_SUCCESS) {
		printf("[%s:%d]\n", __FILE__, __LINE__);
		return rc;
	}

	rc = PROP_CMP_INT(p1, p2, topic_alias);
	if (rc != M5_SUCCESS) {
		printf("[%s:%d]\n", __FILE__, __LINE__);
		return rc;
	}

	rc = PROP_CMP_INT(p1, p2, topic_alias_max);
	if (rc != M5_SUCCESS) {
		printf("[%s:%d]\n", __FILE__, __LINE__);
		return rc;
	}

	rc = PROP_CMP_INT(p1, p2, payload_format_indicator);
	if (rc != M5_SUCCESS) {
		printf("[%s:%d]\n", __FILE__, __LINE__);
		return rc;
	}

	rc = PROP_CMP_INT(p1, p2, max_qos);
	if (rc != M5_SUCCESS) {
		printf("[%s:%d]\n", __FILE__, __LINE__);
		return rc;
	}

	rc = PROP_CMP_INT(p1, p2, retain_available);
	if (rc != M5_SUCCESS) {
		printf("[%s:%d]\n", __FILE__, __LINE__);
		return rc;
	}

	rc = PROP_CMP_INT(p1, p2, wildcard_subscription_available);
	if (rc != M5_SUCCESS) {
		printf("[%s:%d]\n", __FILE__, __LINE__);
		return rc;
	}

	rc = PROP_CMP_INT(p1, p2, subscription_id_available);
	if (rc != M5_SUCCESS) {
		printf("[%s:%d]\n", __FILE__, __LINE__);
		return rc;
	}

	rc = PROP_CMP_INT(p1, p2, shared_subscription_available);
	if (rc != M5_SUCCESS) {
		printf("[%s:%d]\n", __FILE__, __LINE__);
		return rc;
	}

	rc = PROP_CMP_INT(p1, p2, request_response_info);
	if (rc != M5_SUCCESS) {
		printf("[%s:%d]\n", __FILE__, __LINE__);
		return rc;
	}

	rc = PROP_CMP_INT(p1, p2, request_problem_info);
	if (rc != M5_SUCCESS) {
		printf("[%s:%d]\n", __FILE__, __LINE__);
		return rc;
	}

	return M5_SUCCESS;
}

static int null_properties(struct m5_prop *a)
{
	struct m5_prop prop = { 0 };

	return memcmp(a, &prop, sizeof(prop)) == 0 ? 1 : 0;
}

static void add_user_properties(struct m5_prop *prop)
{
	int rc;
	int i;

	for (i = 0; i < M5_USER_PROP_SIZE; i++) {
		rc = m5_prop_add_user_prop(prop, (uint8_t *)"hello", 5,
					   (uint8_t *)"world!", 6);
		if (rc != M5_SUCCESS) {
			DBG("m5_prop_add_user_prop");
			exit(1);
		}
	}
}

#define PROP_PRINT_INT(name)					\
		printf("\t" #name": (0x%x) %u\n",		\
		       p->_ ## name, p->_ ## name)

#define PROP_PRINT_STR(name)					\
		printf("\t" #name": (%u) %.*s\n",		\
		       p->_ ## name ## _len,			\
		       p->_ ## name ## _len,			\
		       p->_ ## name ## _len == 0 ? NULL : p->_ ## name)

#define PROP_PRINT_USER(idx)					\
		printf("\tuser[%d] (%d) %.*s -> (%d) %.*s\n",	\
		       idx,					\
		       p->_user_prop[idx].key_len,		\
		       p->_user_prop[idx].key_len,		\
		       p->_user_prop[idx].key,			\
		       p->_user_prop[idx].value_len,		\
		       p->_user_prop[idx].value_len,		\
		       p->_user_prop[idx].value)

static void print_prop(struct m5_prop *p)
{
	uint32_t i;

	printf("\nMQTT Properties\n");
	PROP_PRINT_STR(auth_method);
	PROP_PRINT_STR(auth_data);
	PROP_PRINT_STR(content_type);
	PROP_PRINT_STR(correlation_data);
	PROP_PRINT_STR(response_info);
	PROP_PRINT_STR(server_reference);
	PROP_PRINT_STR(reason_str);
	PROP_PRINT_STR(assigned_client_id);
	PROP_PRINT_STR(response_topic);

	PROP_PRINT_INT(max_packet_size);
	PROP_PRINT_INT(publication_expiry_interval);
	PROP_PRINT_INT(session_expiry_interval);
	PROP_PRINT_INT(subscription_id);
	PROP_PRINT_INT(will_delay_interval);
	PROP_PRINT_INT(receive_max);
	PROP_PRINT_INT(server_keep_alive);
	PROP_PRINT_INT(topic_alias);
	PROP_PRINT_INT(topic_alias_max);

	PROP_PRINT_INT(payload_format_indicator);
	PROP_PRINT_INT(max_qos);
	PROP_PRINT_INT(retain_available);
	PROP_PRINT_INT(wildcard_subscription_available);
	PROP_PRINT_INT(subscription_id_available);
	PROP_PRINT_INT(shared_subscription_available);
	PROP_PRINT_INT(request_response_info);
	PROP_PRINT_INT(request_problem_info);

	for (i = 0; i < p->_user_len; i++) {
		PROP_PRINT_USER(i);
	}
}

#define DEBUG_PROP_FLAGS(prop, new_prop)			\
	printf("Prev prop flags: 0x%08x, adding: %s\n",		\
	       prop.flags, m5_prop_name[(new_prop)])

static void test_m5_connect(void)
{
	struct app_buf buf = { .data = data, .len = 0, .offset = 0,
			       .size = sizeof(data) };
	char *will_msg = "will msg payload";
	char *client_id = "m5_client";
	char *will_topic = "sensors";
	struct m5_connect msg2 = { 0 };
	struct m5_connect msg = { 0 };
	struct m5_prop prop2 = { 0 };
	struct m5_prop prop = { 0 };
	int rc;

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

	add_user_properties(&prop);

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

	rc = m5_pack_connect(&ctx, &buf, &msg, &prop);
	if (rc != M5_SUCCESS) {
		DBG("m5_pack_connect");
		exit(1);
	}

	printf("CONNECT\n");
	print_buf(&buf);

	buf.offset = 0;
	rc = m5_unpack_connect(&ctx, &buf, &msg2, &prop2);
	if (rc != M5_SUCCESS) {
		DBG("m5_unpack_connect");
		exit(1);
	}

	rc = cmp_prop(&prop, &prop2);
	if (rc != M5_SUCCESS) {
		DBG("cmp_prop");
		print_prop(&prop);
		print_prop(&prop2);
		exit(1);
	}

	printf("\nCONNECT Payload\n");
	printf("\tClient Id: %.*s\n", (int)msg2.client_id_len,
				    (char *)msg2.client_id);
	printf("\tWill topic: %.*s\n", (int)msg2.will_topic_len,
				     (char *)msg2.will_topic);
	printf("\tWill msg: %.*s\n", (int)msg2.will_msg_len,
				   (char *)msg2.will_msg);
	printf("\tUser name: %.*s\n", (int)msg2.user_name_len,
				    (char *)msg2.user_name);
	printf("\tPassword: %.*s\n", (int)msg2.password_len,
				   (char *)msg2.password);
	printf("\tKeep alive: %u\n", msg2.keep_alive);
	printf("\tWill retain: %s\n", msg2.will_retain == 1 ? "yes" : "no");
	printf("\tWill QoS: %u\n", msg2.will_qos);
	printf("\tClean start: %s\n", msg2.clean_start == 1 ? "yes" : "no");
}

static void test_m5_connack(void)
{
	struct app_buf buf = { .data = data, .len = 0, .offset = 0,
			       .size = sizeof(data) };
	struct m5_connack msg = { 0 };
	struct m5_prop prop2 = { 0 };
	struct m5_prop prop = { 0 };
	int rc;

	TEST_HDR(__func__);

	msg.return_code = 0x01;
	msg.session_present = 0x01;

	m5_prop_receive_max(&prop, 0xABCD);
	m5_prop_max_qos(&prop, M5_QoS2);
	m5_prop_retain_available(&prop, 1);
	m5_prop_max_packet_size(&prop, 0x0102ABCD);
	m5_prop_assigned_client_id(&prop, (uint8_t *)"assigned", 8);
	m5_prop_topic_alias_max(&prop, 0xABCD);
	m5_prop_reason_str(&prop, (uint8_t *)"reason", 6);

	add_user_properties(&prop);

	m5_prop_wildcard_subscription_available(&prop, 1);
	m5_prop_subscription_id_available(&prop, 1);
	m5_prop_shared_subscription_available(&prop, 1);
	m5_prop_server_keep_alive(&prop, 0x0123);
	m5_prop_response_info(&prop, (uint8_t *)"response", 8);
	m5_prop_server_reference(&prop, (uint8_t *)"reference", 9);
	m5_prop_auth_method(&prop, (uint8_t *)"auth method", 11);
	m5_prop_auth_data(&prop, (uint8_t *)"auth_data", 9);

	rc = m5_pack_connack(&ctx, &buf, &msg, &prop);
	if (rc != M5_SUCCESS) {
		DBG("m5_pack_connack");
		exit(1);
	}

	buf.offset = 0;
	rc = m5_unpack_connack(&ctx, &buf, &msg, &prop2);
	if (rc != M5_SUCCESS) {
		DBG("m5_unpack_connack");
		exit(1);
	}

	rc = cmp_prop(&prop, &prop2);
	if (rc != M5_SUCCESS) {
		DBG("cmp_prop");
		print_prop(&prop);
		print_prop(&prop2);
		exit(1);
	}

	printf("CONNACK\n");
	printf("CONNACK flags: 0x%02x\n", msg.session_present);
	printf("CONNACK rc: 0x%02x\n", msg.return_code);
	print_buf(&buf);
}

static int cmp_publish(struct m5_publish *a, struct m5_publish *b)
{
	if (a->payload_len != b->payload_len) {
		return M5_INVALID_ARGUMENT;
	}

	if (a->topic_name_len != b->topic_name_len) {
		return M5_INVALID_ARGUMENT;
	}

	if (a->packet_id != b->packet_id) {
		return M5_INVALID_ARGUMENT;
	}

	if (a->dup != b->dup) {
		return M5_INVALID_ARGUMENT;
	}

	if (a->qos != b->qos) {
		return M5_INVALID_ARGUMENT;
	}

	if (a->retain != b->retain) {
		return M5_INVALID_ARGUMENT;
	}

	if (memcmp(a->payload, b->payload, a->payload_len) != 0) {
		return M5_INVALID_ARGUMENT;
	}

	if (memcmp(a->topic_name, b->topic_name, a->topic_name_len) != 0) {
		return M5_INVALID_ARGUMENT;
	}

	return M5_SUCCESS;
}

static void test_m5_publish_full(void)
{
	struct app_buf buf = { .data = data, .len = 0, .offset = 0,
			       .size = sizeof(data) };
	struct m5_publish msg2 = { 0 };
	struct m5_publish msg = { 0 };
	struct m5_prop prop2 = { 0 };
	struct m5_prop prop = { 0 };
	int rc;

	TEST_HDR(__func__);

	msg.dup = 1;
	msg.qos = M5_QoS1;
	msg.retain = 1;
	msg.packet_id = 0x1234;
	msg.topic_name = (uint8_t *)"topic";
	msg.topic_name_len = strlen((char *)msg.topic_name);
	msg.payload = (uint8_t *)"hello";
	msg.payload_len = strlen((char *)msg.payload);

	m5_prop_payload_format_indicator(&prop, 0xAB);
	m5_prop_publication_expiry_interval(&prop, 0x12);
	m5_prop_topic_alias(&prop, 0x12);
	m5_prop_response_topic(&prop, (uint8_t *)"topic", 5);
	m5_prop_correlation_data(&prop, (uint8_t *)"data", 4);

	add_user_properties(&prop);

	m5_prop_subscription_id(&prop, 0x12);
	m5_prop_content_type(&prop, (uint8_t *)"data", 4);

	rc = m5_pack_publish(&ctx, &buf, &msg, &prop);
	if (rc != M5_SUCCESS) {
		DBG("m5_pack_publish");
		exit(1);
	}

	buf.offset = 0;
	rc = m5_unpack_publish(&ctx, &buf, &msg2, &prop2);
	if (rc != M5_SUCCESS) {
		DBG("m5_unpack_publish");
		exit(1);
	}

	print_buf(&buf);

	rc = cmp_publish(&msg, &msg2);
	if (rc != M5_SUCCESS) {
		DBG("cmp_publish");
		exit(1);
	}

	rc = cmp_prop(&prop, &prop2);
	if (rc != M5_SUCCESS) {
		DBG("cmp_prop");
		print_prop(&prop);
		print_prop(&prop2);
		exit(1);
	}

	printf("Publish packed payload:   ");
	print_raw((void *)msg.payload, msg.payload_len);
	printf("Publish unpacked payload: ");
	print_raw((void *)msg2.payload, msg2.payload_len);
}

static void test_m5_publish_short(void)
{
	struct app_buf buf = { .data = data, .len = 0, .offset = 0,
			       .size = sizeof(data) };
	struct m5_publish msg2 = { 0 };
	struct m5_publish msg = { 0 };
	struct m5_prop prop2 = { 0 };
	int rc;

	TEST_HDR(__func__);

	msg.dup = 1;
	msg.qos = M5_QoS0;
	msg.retain = 1;
	msg.topic_name = (uint8_t *)"topic";
	msg.topic_name_len = strlen((char *)msg.topic_name);

	rc = m5_pack_publish(&ctx, &buf, &msg, NULL);
	if (rc != M5_SUCCESS) {
		DBG("m5_pack_publish");
		exit(1);
	}

	buf.offset = 0;
	rc = m5_unpack_publish(&ctx, &buf, &msg2, &prop2);
	if (rc != M5_SUCCESS) {
		DBG("m5_unpack_publish");
		exit(1);
	}

	rc = cmp_publish(&msg, &msg2);
	if (rc != M5_SUCCESS) {
		DBG("cmp_publish");
		exit(1);
	}

	if (null_properties(&prop2) != 1) {
		DBG("m5_unpack_publish: properties");
		exit(1);
	}

	print_buf(&buf);
}

static void test_m5_publish(void)
{
	test_m5_publish_short();
	test_m5_publish_full();
}

/* XXX
 * Add the PUB response test case
 */


static int compare_topics(struct m5_topics *t1, struct m5_topics *t2)
{
	uint8_t i;
	int rc;

	TEST_HDR(__func__);

	if (t1->items != t2->items) {
		printf("[%s:%d]\n", __FILE__, __LINE__);
		return M5_INVALID_ARGUMENT;
	}

	for (i = 0; i < t1->items; i++) {
		rc = cmp_str(t1->topics[i], t1->len[i],
			     t2->topics[i], t2->len[i]);
		if (rc != 0) {
			printf("[%s:%d]\n", __FILE__, __LINE__);
			return M5_INVALID_ARGUMENT;
		}
	}

	return M5_SUCCESS;
}

static void test_m5_subscribe(void)
{
	struct app_buf buf = { .data = data, .len = 0, .offset = 0,
			       .size = sizeof(data) };
	uint8_t *topics[] = {(uint8_t *)"sensors", (uint8_t *)"doors",
			     (uint8_t *)"windows"};
	uint8_t options[] = {M5_QoS0, M5_QoS1, M5_QoS2};
	uint16_t topics_len[] = {7, 5, 7};
	struct m5_subscribe msg2 = { 0 };
	struct m5_subscribe msg = { 0 };
	struct m5_prop prop2 = { 0 };
	struct m5_prop prop = { 0 };
	uint16_t topics_len2[3];
	uint8_t *topics2[3];
	uint8_t options2[3];
	int rc;

	TEST_HDR(__func__);

	msg.packet_id = 0xABCD;
	msg.topics.items = 3;
	msg.topics.size = 3;
	msg.options = options;
	msg.topics.topics = topics;
	msg.topics.len = topics_len;

	m5_prop_subscription_id(&prop, 0x1234);
	rc = m5_pack_subscribe(&ctx, &buf, &msg, &prop);
	if (rc != M5_SUCCESS) {
		DBG("m5_pack_subscribe");
		exit(1);
	}

	printf("Subscribe\n");
	print_buf(&buf);

	msg2.topics.items = 0;
	msg2.options = options2;
	msg2.topics.topics = topics2;
	msg2.topics.len = topics_len2;
	msg2.topics.size = 3;

	buf.offset = 0;
	rc = m5_unpack_subscribe(&ctx, &buf, &msg2, &prop2);
	if (rc != M5_SUCCESS) {
		DBG("m5_unpack_subscribe");
		exit(1);
	}

	rc = cmp_prop(&prop, &prop2);
	if (rc != M5_SUCCESS) {
		DBG("cmp_prop");
		print_prop(&prop);
		print_prop(&prop2);
		exit(1);
	}

	rc = compare_topics(&msg.topics, &msg2.topics);
	if (rc != M5_SUCCESS) {
		DBG("compare_topics");
		exit(1);
	}
}

static void test_m5_suback(void)
{
	struct app_buf buf = { .data = data, .len = 0, .offset = 0,
			       .size = sizeof(data) };
	uint8_t reason_code[] = {M5_QoS0, M5_QoS1, M5_QoS2};
	struct m5_suback msg2 = { 0 };
	struct m5_suback msg = { 0 };
	struct m5_prop prop2 = { 0 };
	struct m5_prop prop = { 0 };
	uint8_t reason_code2[3];
	int rc;

	TEST_HDR(__func__);

	msg.packet_id = 0x1234;
	msg.rc_items = 3;
	msg.rc_size = 3;
	msg.rc = reason_code;

	m5_prop_reason_str(&prop, (uint8_t *)"reason", 6);

	add_user_properties(&prop);

	rc = m5_pack_suback(&ctx, &buf, &msg, &prop);
	if (rc != M5_SUCCESS) {
		DBG("m5_pack_suback");
		exit(1);
	}

	printf("SUBACK\n");
	print_buf(&buf);

	msg2.rc_items = 0;
	msg2.rc_size = 3;
	msg2.rc = reason_code2;

	buf.offset = 0;
	rc = m5_unpack_suback(&ctx, &buf, &msg2, &prop2);
	if (rc != M5_SUCCESS) {
		DBG("m5_unpack_suback");
		exit(1);
	}

	rc = cmp_prop(&prop, &prop2);
	if (rc != M5_SUCCESS) {
		DBG("cmp_prop");
		print_prop(&prop);
		print_prop(&prop2);
		exit(1);
	}
}

static void test_m5_unsubscribe(void)
{
	struct app_buf buf = { .data = data, .len = 0, .offset = 0,
			       .size = sizeof(data) };
	uint8_t *topics[] = {(uint8_t *)"sensors", (uint8_t *)"doors",
			     (uint8_t *)"windows"};
	struct m5_unsubscribe msg2 = { 0 };
	struct m5_unsubscribe msg = { 0 };
	uint16_t topics_len[] = {7, 5, 7};
	uint16_t topics_len2[3];
	uint8_t *t2[3];
	int rc;

	TEST_HDR(__func__);

	msg.packet_id = 0x1234;
	msg.topics.items = 3;
	msg.topics.size = 3;
	msg.topics.topics = topics;
	msg.topics.len = topics_len;

	rc = m5_pack_unsubscribe(&ctx, &buf, &msg);
	if (rc != M5_SUCCESS) {
		DBG("m5_pack_unsubscribe");
		exit(1);
	}

	printf("UNSUBSCRIBE\n");
	print_buf(&buf);

	msg2.topics.items = 0;
	msg2.topics.topics = t2;
	msg2.topics.len = topics_len2;
	msg2.topics.size = 3;

	buf.offset = 0;
	rc = m5_unpack_unsubscribe(&ctx, &buf, &msg2);
	if (rc != M5_SUCCESS) {
		DBG("m5_unpack_unsubscribe");
		exit(1);
	}

	rc = compare_topics(&msg.topics, &msg2.topics);
	if (rc != M5_SUCCESS) {
		DBG("compare_topics");
		exit(1);
	}
}

static void test_m5_unsuback(void)
{
	struct app_buf buf = { .data = data, .len = 0, .offset = 0,
			       .size = sizeof(data) };
	uint8_t reason_code[] = {M5_QoS0, M5_QoS1, M5_QoS2};
	uint8_t reason_code_read[3];
	struct m5_prop prop2 = { 0 };
	struct m5_prop prop = { 0 };
	struct m5_suback msg = { 0 };
	struct m5_suback msg2 = { .rc_size = 3, .rc = reason_code_read };
	uint16_t pkt_id = 0x1234;
	int rc;

	TEST_HDR(__func__);

	msg.packet_id = pkt_id;
	msg.rc = reason_code;
	msg.rc_items = 3;
	msg.rc_size = 3;

	m5_prop_reason_str(&prop, (uint8_t *)"reason", 6);

	add_user_properties(&prop);

	rc = m5_pack_unsuback(&ctx, &buf, &msg, &prop);
	if (rc != M5_SUCCESS) {
		DBG("m5_pack_unsuback");
		exit(1);
	}

	printf("UNSUBACK\n");
	print_buf(&buf);

	buf.offset = 0;
	rc = m5_unpack_unsuback(&ctx, &buf, &msg2, &prop2);
	if (rc != M5_SUCCESS) {
		DBG("m5_unpack_unsuback");
		exit(1);
	}

	rc = cmp_prop(&prop, &prop2);
	if (rc != M5_SUCCESS) {
		DBG("cmp_prop");
		print_prop(&prop);
		print_prop(&prop2);
		exit(1);
	}
}

typedef int (*ptr_ping)(struct m5_ctx *, struct app_buf *);

static void test_m5_pings(ptr_ping pack, ptr_ping unpack)
{
	struct app_buf buf = { .data = data, .len = 0, .offset = 0,
			       .size = sizeof(data) };
	int rc;

	rc = pack(&ctx, &buf);
	if (rc != M5_SUCCESS) {
		DBG("pack");
		exit(1);
	}

	print_buf(&buf);

	buf.offset = 0;
	rc = unpack(&ctx, &buf);
	if (rc != M5_SUCCESS) {
		DBG("unpack");
		exit(1);
	}
}

static void test_m5_pingreq(void)
{
	TEST_HDR(__func__);

	test_m5_pings(m5_pack_pingreq, m5_unpack_pingreq);
}

static void test_m5_pingresp(void)
{
	TEST_HDR(__func__);

	test_m5_pings(m5_pack_pingresp, m5_unpack_pingresp);
}

static void test_m5_disconnect(void)
{
	struct app_buf buf = { .data = data, .len = 0, .offset = 0,
			       .size = sizeof(data) };
	struct m5_prop prop2 = { 0 };
	struct m5_prop prop = { 0 };
	uint8_t reason_code;
	int rc;

	TEST_HDR(__func__);

	m5_prop_session_expiry_interval(&prop, 0x1234);
	m5_prop_reason_str(&prop, (uint8_t *)"reason", 6);

	add_user_properties(&prop);

	m5_prop_server_reference(&prop, (uint8_t *)"reference", 9);

	m5_prop_session_expiry_interval(&prop, 0x1234);
	rc = m5_pack_disconnect(&ctx, &buf, M5_RC_PROTOCOL_ERROR, &prop);
	if (rc != M5_SUCCESS) {
		DBG("m5_pack_disconnect");
		exit(1);
	}

	buf.offset = 0;
	rc = m5_unpack_disconnect(&ctx, &buf, &reason_code, &prop2);
	if (rc != M5_SUCCESS) {
		DBG("m5_unpack_disconnect");
		exit(1);
	}

	printf("DISCONNECT\n");
	print_buf(&buf);

	rc = cmp_prop(&prop, &prop2);
	if (rc != M5_SUCCESS) {
		DBG("cmp_prop");
		print_prop(&prop);
		print_prop(&prop2);
		exit(1);
	}
}

typedef int (*ptr_pack)(struct m5_ctx *, struct app_buf *,
		      uint8_t, struct m5_prop *);

typedef int (*ptr_unpack)(struct m5_ctx *, struct app_buf *,
			  uint8_t *, struct m5_prop *);

static void test_m5_disconnect_auth_short(ptr_pack pack,
					  ptr_unpack unpack,
					  const char *str)
{
	struct app_buf buf = { .data = data, .len = 0, .offset = 0,
			       .size = sizeof(data) };
	uint8_t reason_code = 0x00;
	int rc;

	rc = pack(&ctx, &buf, reason_code, NULL);
	if (rc != M5_SUCCESS) {
		DBG("pack");
		exit(1);
	}

	buf.offset = 0;
	rc = unpack(&ctx, &buf, &reason_code, NULL);
	if (rc != M5_SUCCESS) {
		DBG("unpack");
		exit(1);
	}

	if (reason_code != 0) {
		DBG("pack/unpack");
		exit(1);
	}

	printf("%s (no reason code / properties)\n", str);
	print_buf(&buf);
}

static void test_m5_disconnect_short(void)
{
	TEST_HDR(__func__);

	test_m5_disconnect_auth_short(m5_pack_disconnect,
				      m5_unpack_disconnect,
				      "DISCONNECT");

}

static void test_m5_auth_short(void)
{
	TEST_HDR(__func__);

	test_m5_disconnect_auth_short(m5_pack_auth,
				      m5_unpack_auth,
				      "AUTH");

}

static void test_m5_auth(void)
{
	struct app_buf buf = { .data = data, .len = 0, .offset = 0,
			       .size = sizeof(data) };
	struct m5_prop prop2 = { 0 };
	struct m5_prop prop = { 0 };
	uint8_t ret_code;
	int rc;

	TEST_HDR(__func__);

	m5_prop_auth_method(&prop, (uint8_t *)"method", 6);
	m5_prop_auth_data(&prop, (uint8_t *)"method_payload", 14);

	add_user_properties(&prop);

	rc = m5_pack_auth(&ctx, &buf, M5_RC_CONTINUE_AUTHENTICATION, &prop);
	if (rc != M5_SUCCESS) {
		DBG("m5_pack_auth");
		exit(1);
	}

	buf.offset = 0;
	rc = m5_unpack_auth(&ctx, &buf, &ret_code, &prop2);
	if (rc != M5_SUCCESS) {
		DBG("m5_unpack_auth");
		exit(1);
	}

	printf("AUTH\n");
	print_buf(&buf);

	rc = cmp_prop(&prop, &prop2);
	if (rc != M5_SUCCESS) {
		DBG("cmp_prop");
		print_prop(&prop);
		print_prop(&prop2);
		exit(1);
	}
}

int main(void)
{
	test_int_encoding();
	test_m5_add_u16();
	test_m5_add_str();
	test_m5_connect();
	test_m5_connack();
	test_m5_publish();
	test_m5_subscribe();
	test_m5_suback();
	test_m5_unsubscribe();
	test_m5_unsuback();
	test_m5_pingreq();
	test_m5_pingresp();
	test_m5_disconnect_short();
	test_m5_disconnect();
	test_m5_auth_short();
	test_m5_auth();

	return 0;
}
