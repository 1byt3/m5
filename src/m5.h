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

#ifndef __M5_H__
#define __M5_H__

#include <inttypes.h>
#include <stddef.h>

/*
 * App buffer data structure
 */
struct app_buf {
	uint8_t *data;
	size_t offset;

	size_t size;
	size_t len;
};

enum m5_protocol {
	M5_5 = 5
};

enum m5_qos {
	M5_QoS0 = 0,
	M5_QoS1,
	M5_QoS2
};

enum m5_pkt_type {
	M5_PKT_RESERVED = 0,
	M5_PKT_CONNECT,
	M5_PKT_CONNACK,
	M5_PKT_PUBLISH,
	M5_PKT_PUBACK,
	M5_PKT_PUBREC,
	M5_PKT_PUBREL,
	M5_PKT_PUBCOMP,
	M5_PKT_SUBSCRIBE,
	M5_PKT_SUBACK,
	M5_PKT_UNSUBSCRIBE,
	M5_PKT_UNSUBACK,
	M5_PKT_PINGREQ,
	M5_PKT_PINGRESP,
	M5_PKT_DISCONNECT,
	M5_PKT_AUTH
};

enum m5_reason_code {
	M5_RC_SUCCESS = 0,
	M5_RC_NORMAL_DISCONNECTION = 0,
	M5_RC_GRANTED_QOS0 = 0,
	M5_RC_GRANTED_QOS1,
	M5_RC_GRANTED_QOS2,
	M5_RC_DISCONNECT_WILL = 4,
	M5_RC_NO_MATCHING_SUBSCRIBERS = 16,
	M5_RC_NO_SUBSCRIPTION_EXISTED,
	M5_RC_CONTINUE_AUTHENTICATION = 24,
	M5_RC_RE_AUTHENTICATE,
	M5_RC_UNSPECIFIED_ERROR = 128,
	M5_RC_MALFORMED_PACKET,
	M5_RC_PROTOCOL_ERROR,
	M5_RC_IMPLEMENTATION_SPECIFIC_ERROR,
	M5_RC_UNSUPPORTED_PROTOCOL_VERSION,
	M5_RC_CLIENT_IDENTIFIER_NOT_VALID,
	M5_RC_BAD_USER_NAME_OR_PASSWORD,
	M5_RC_NOT_AUTHORIZED,
	M5_RC_SERVER_UNAVAILABLE,
	M5_RC_SERVER_BUSY,
	M5_RC_BANNED,
	M5_RC_SERVER_SHUTTING_DOWN,
	M5_RC_BAD_AUTHENTICATION_METHOD,
	M5_RC_KEEP_ALIVE_TIMEOUT,
	M5_RC_SESSION_TAKEN_OVER,
	M5_RC_TOPIC_FILTER_INVALID,
	M5_RC_TOPIC_NAME_INVALID,
	M5_RC_PACKET_IDENTIFIER_IN_USE,
	M5_RC_PACKET_IDENTIFIER_NOT_FOUND,
	M5_RC_RECEIVE_MAXIMUM_EXCEEDED,
	M5_RC_TOPIC_ALIAS_INVALID,
	M5_RC_PACKET_TOO_LARGE,
	M5_RC_MESSAGE_RATE_TOO_HIGH,
	M5_RC_QUOTA_EXCEEDED,
	M5_RC_ADMINISTRATIVE_ACTION,
	M5_RC_PAYLOAD_FORMAT_INVALID,
	M5_RC_RETAIN_NOT_SUPPORTED,
	M5_RC_QOS_NOT_SUPPORTED,
	M5_RC_USE_ANOTHER_SERVER,
	M5_RC_SERVER_MOVED,
	M5_RC_SHARED_SUBSCRIPTION_NOT_SUPPORTED,
	M5_RC_CONNECTION_RATE_EXCEEDED,
	M5_RC_MAXIMUM_CONNECT_TIME,
	M5_RC_SUBSCRIPTION_IDENTIFIERS_NOT_SUPPORTED,
	M5_RC_WILDCARD_SUBSCRIPTION_NOT_SUPPORTED
};

struct m5_user_prop {
	uint8_t *key;
	uint8_t *value;

	uint16_t key_len;
	uint16_t value_len;
};

struct m5_prop {
#ifndef M5_USER_PROP_SIZE
	#define M5_USER_PROP_SIZE 0
	struct m5_user_prop *_user_prop;
#else
	struct m5_user_prop _user_prop[M5_USER_PROP_SIZE];
#endif
	uint8_t *_auth_method;
	uint8_t *_auth_data;
	uint8_t *_content_type;
	uint8_t *_correlation_data;
	uint8_t *_response_info;
	uint8_t *_server_reference;
	uint8_t *_reason_str;
	uint8_t *_assigned_client_id;
	uint8_t *_response_topic;

	uint32_t flags;

	uint32_t _max_packet_size;
	uint32_t _publication_expiry_interval;
	uint32_t _session_expiry_interval;
	uint32_t _subscription_id;
	uint32_t _will_delay_interval;

	uint32_t _user_prop_wsize;

	uint16_t _receive_max;
	uint16_t _server_keep_alive;
	uint16_t _topic_alias;
	uint16_t _topic_alias_max;

	uint8_t _auth_method_len;
	uint8_t _auth_data_len;
	uint8_t _content_type_len;
	uint8_t _correlation_data_len;
	uint8_t _response_info_len;
	uint8_t _server_reference_len;
	uint8_t _reason_str_len;
	uint8_t _assigned_client_id_len;
	uint8_t _response_topic_len;

	uint8_t _payload_format_indicator;
	uint8_t _max_qos;
	uint8_t _retain_available;
	uint8_t _wildcard_subscription_available;
	uint8_t _subscription_id_available;
	uint8_t _shared_subscription_available;

	/* Number of elements in the User Properties array */
	uint8_t _user_len;

	uint8_t _request_response_info;
	uint8_t _request_problem_info;
};

struct m5_connect {
	uint8_t *client_id;
	uint8_t *will_topic;
	uint8_t *will_msg;
	uint8_t *user_name;
	uint8_t *password;

	uint16_t client_id_len;
	uint16_t will_topic_len;
	uint16_t will_msg_len;
	uint16_t user_name_len;
	uint16_t password_len;

	uint16_t keep_alive;

	uint8_t will_retain;
	uint8_t will_qos;
	uint8_t clean_start;
};

struct m5_connack {
	uint8_t session_present;
	uint8_t return_code;
};

struct m5_publish {
	uint8_t *payload;
	uint8_t *topic_name;

	uint32_t payload_len;

	uint16_t topic_name_len;
	uint16_t packet_id;

	uint8_t dup;
	uint8_t qos;
	uint8_t retain;
};

struct m5_pub_response {
	uint16_t packet_id;
	uint8_t reason_code;
};

struct m5_topics {
	uint8_t **topics;
	uint16_t *len;

	uint16_t items;
	uint16_t size;
};

struct m5_subscribe {
	struct m5_topics topics;
	uint8_t *options;

	uint16_t packet_id;
};

struct m5_suback {
	uint8_t *rc;

	uint16_t packet_id;

	uint8_t rc_size;
	uint8_t rc_items;
};

struct m5_unsubscribe {
	struct m5_topics topics;

	uint16_t packet_id;
};

void m5_prop_payload_format_indicator(struct m5_prop *prop, uint8_t v);

void m5_prop_publication_expiry_interval(struct m5_prop *prop, uint32_t v);

void m5_prop_content_type(struct m5_prop *prop,
			  uint8_t *data, uint16_t data_len);

void m5_prop_response_topic(struct m5_prop *prop,
			    uint8_t *data, uint16_t data_len);

void m5_prop_correlation_data(struct m5_prop *prop,
			      uint8_t *data, uint16_t data_len);

void m5_prop_subscription_id(struct m5_prop *prop, uint32_t v);

void m5_prop_session_expiry_interval(struct m5_prop *prop, uint32_t v);

void m5_prop_assigned_client_id(struct m5_prop *prop,
				uint8_t *data, uint16_t data_len);

void m5_prop_server_keep_alive(struct m5_prop *prop, uint16_t v);

void m5_prop_auth_method(struct m5_prop *prop, uint8_t *d, uint16_t d_len);

void m5_prop_auth_data(struct m5_prop *prop, uint8_t *d, uint16_t d_len);

void m5_prop_request_problem_info(struct m5_prop *prop, uint8_t v);

void m5_prop_will_delay_interval(struct m5_prop *prop, uint32_t v);

void m5_prop_request_response_info(struct m5_prop *prop, uint8_t v);

void m5_prop_response_info(struct m5_prop *prop, uint8_t *d, uint16_t d_len);

void m5_prop_server_reference(struct m5_prop *prop, uint8_t *d, uint16_t d_len);

void m5_prop_reason_str(struct m5_prop *prop, uint8_t *d, uint16_t d_len);

void m5_prop_receive_max(struct m5_prop *prop, uint16_t v);

void m5_prop_topic_alias_max(struct m5_prop *prop, uint16_t v);

void m5_prop_topic_alias(struct m5_prop *prop, uint16_t v);

void m5_prop_max_qos(struct m5_prop *prop, uint8_t v);

void m5_prop_retain_available(struct m5_prop *prop, uint8_t v);

int m5_prop_add_user_prop(struct m5_prop *prop,
			  uint8_t *key, uint16_t key_len,
			  uint8_t *value, uint16_t value_len);

void m5_prop_max_packet_size(struct m5_prop *prop, uint32_t v);

void m5_prop_wildcard_subscription_available(struct m5_prop *prop, uint8_t v);

void m5_prop_subscription_id_available(struct m5_prop *prop, uint8_t v);

void m5_prop_shared_subscription_available(struct m5_prop *prop, uint8_t v);

int m5_pack_connect(struct app_buf *buf, struct m5_connect *msg,
		    struct m5_prop *prop);

int m5_unpack_connect(struct app_buf *buf, struct m5_connect *msg,
		      struct m5_prop *prop);

int m5_pack_connack(struct app_buf *buf, struct m5_connack *msg,
		    struct m5_prop *prop);

int m5_unpack_connack(struct app_buf *buf, struct m5_connack *msg,
		      struct m5_prop *prop);

int m5_pack_publish(struct app_buf *buf, struct m5_publish *msg,
		    struct m5_prop *prop);

int m5_unpack_publish(struct app_buf *buf, struct m5_publish *msg,
		      struct m5_prop *prop);

int m5_pack_puback(struct app_buf *buf, struct m5_pub_response *msg,
		   struct m5_prop *prop);

int m5_unpack_puback(struct app_buf *buf, struct m5_pub_response *msg,
		     struct m5_prop *prop);

int m5_pack_pubrec(struct app_buf *buf, struct m5_pub_response *msg,
		   struct m5_prop *prop);

int m5_unpack_pubrec(struct app_buf *buf, struct m5_pub_response *msg,
		     struct m5_prop *prop);

int m5_pack_pubrel(struct app_buf *buf, struct m5_pub_response *msg,
		   struct m5_prop *prop);

int m5_unpack_pubrel(struct app_buf *buf, struct m5_pub_response *msg,
		     struct m5_prop *prop);

int m5_pack_pubcomp(struct app_buf *buf, struct m5_pub_response *msg,
		    struct m5_prop *prop);

int m5_unpack_pubcomp(struct app_buf *buf, struct m5_pub_response *msg,
		      struct m5_prop *prop);

int m5_pack_subscribe(struct app_buf *buf, struct m5_subscribe *msg,
		      struct m5_prop *prop);

int m5_unpack_subscribe(struct app_buf *buf, struct m5_subscribe *msg,
			struct m5_prop *prop);

int m5_pack_suback(struct app_buf *buf, struct m5_suback *msg,
		    struct m5_prop *prop);

int m5_unpack_suback(struct app_buf *buf, struct m5_suback *msg,
		     struct m5_prop *prop);

int m5_pack_unsubscribe(struct app_buf *buf, struct m5_unsubscribe *msg);

int m5_unpack_unsubscribe(struct app_buf *buf, struct m5_unsubscribe *msg);

int m5_pack_unsuback(struct app_buf *buf, uint16_t packet_id,
		     struct m5_prop *prop);

int m5_unpack_unsuback(struct app_buf *buf, uint16_t *packet_id,
		       struct m5_prop *prop);

#endif
