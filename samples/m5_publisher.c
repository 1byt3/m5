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

#if defined(__FreeBSD__)
#include <sys/endian.h>
#else
#include <endian.h>
#endif

#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <signal.h>

#define PEER_ADDR           { 127, 0, 0, 1 }
#define PEER_PORT           1883

#define CLIENT_ID           "m5_publisher"
#define TOPIC_NAME          "greetings"
#define PUBLISH_PAYLOAD     "Hello, World!"

#define MAX_PACKET_ID       32

static int loop_forever;

static int publish(int fd)
{
        static struct m5_topic topic_filters[] = {
        { .name = (uint8_t *)"srv/one", .len = 7, .options = M5_QoS1 },
        { .name = (uint8_t *)"sensors", .len = 7, .options = M5_QoS2 },
        { .name = (uint8_t *)"doors",   .len = 5, .options = M5_QoS0 },
        { .name = NULL } };

        struct m5_publish msg = { 0 };
        static uint16_t packet_id = 1;
        static int i = -1;
        int rc;

        i = (i + 1) % 3;

        msg.payload = (uint8_t *)PUBLISH_PAYLOAD;
        msg.payload_len = strlen(PUBLISH_PAYLOAD);
        msg.topic_name = topic_filters[i].name;
        msg.topic_name_len = topic_filters[i].len;
        msg.qos = topic_filters[i].options;

        if (msg.qos != M5_QoS0) {
                msg.packet_id = packet_id;
                packet_id = 1 + packet_id%(MAX_PACKET_ID - 1);
        }

        rc = publish_message(fd, &msg, &loop_forever);
        if (rc != 0) {
                DBG("publish_message");
                return -1;
        }

        return 0;
}

static int publisher(void)
{
        uint8_t peer_addr[] = PEER_ADDR;
        int socket_fd;
        int rc;

        rc = client_connect(&socket_fd, CLIENT_ID, peer_addr, PEER_PORT);
        if (rc != 0) {
                DBG("publisher_connect");
                goto lb_exit;
        }

        while (loop_forever) {
                rc = publish(socket_fd);
                if (rc != 0) {
                        DBG("publish");
                        goto lb_close;
                }

                sleep(1);
        }

        rc = 0;

lb_close:
        printf("Connection closed\n");
        client_disconnect(socket_fd, M5_RC_NORMAL_DISCONNECTION);

lb_exit:
        return rc;
}

static void signal_handler(int id)
{
        (void)id;

        printf("\n\t\tBye!\n\n");
        loop_forever = 0;
}

int main(void)
{
        set_tcp_timeout(5); /* seconds */

        loop_forever = 1;

        signal(SIGPIPE, signal_handler);
        signal(SIGTERM, signal_handler);
        signal(SIGINT, signal_handler);

        return publisher();
}
