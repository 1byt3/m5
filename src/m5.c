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
#include <errno.h>

#define APPBUF_FREE_READ_SPACE(buf) (buf->len - buf->offset)
#define APPBUF_FREE_WRITE_SPACE(buf) (buf->size - buf->len)
#define APPBUF_DATAPTR_CURRENT(buf) (buf->data + buf->offset)

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
