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

#ifdef M5_USER_PROP_SIZE
#undef M5_USER_PROP_SIZE
#endif

#ifdef M5_SKIP_ON_FULL_USER_PROP
#undef M5_SKIP_ON_FULL_USER_PROP
#endif

#define M5_SKIP_ON_FULL_USER_PROP 1

#include "test_common.h"
#include "m5.c"

#include <string.h>
#include <stdio.h>

static void test_user_prop(void)
{
        struct m5_prop prop = { 0 };

        char hello_world[] = "Hello, World!";
        uint16_t data_len;
        uint8_t *data;
        int rc;

        TEST_HDR(__func__);

        data = (uint8_t *)hello_world;
        data_len = strlen(hello_world);

        /* This will not fail because M5_SKIP_ON_FULL_USER_PROP is 1 */
        rc = m5_prop_add_user_prop(&prop, data, data_len, data, data_len);
        if (rc != M5_SUCCESS) {
                DBG("m5_prop_add_user_prop");
                exit(-1);
        }
}

int main(void)
{
        test_user_prop();

        return 0;
}
