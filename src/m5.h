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

#endif
