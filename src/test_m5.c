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

int main(void)
{
	test_int_encoding();
	test_m5_add_u16();
	test_m5_add_str();

	return 0;
}
