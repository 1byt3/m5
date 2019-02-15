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
#include "m5.h"

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

#define LISTEN_ADDR         { 127, 0, 0, 1 }
#define LISTEN_PORT         1863

#define PUBLISH_PAYLOAD     "Hello, World!"

#define MAX_PACKET_ID       32

static int working_pipe;
static int loop_forever;

/* Keep the subscriber info available for future by the publisher app */
uint8_t topic_data[MAX_BUF_SIZE];
static struct m5_topic topics[MAX_ARRAY_ELEMENTS] = { 0 };
static uint8_t topic_items;

static int validate_connect(enum m5_pkt_type pkt_type, void *msg, void *user)
{
        (void)msg;
        (void)user;

        if (pkt_type == M5_PKT_CONNECT) {
                return 0;
        }

        return -1;
}

static int fill_topics(struct m5_subscribe *msg)
{
        uint32_t offset = 0;
        uint8_t i;

        if (msg->items > MAX_ARRAY_ELEMENTS) {
                DBG("subscribe items > MAX_ARRAY_ELEMENTS");
                return -1;
        }

        for (i = 0; i < msg->items; i++) {
                uint16_t size = msg->topics[i].len;

                if (offset + size > MAX_BUF_SIZE) {
                        DBG("offset + size > MAX_BUF_SIZE");
                        return -1;
                }

                memcpy(topic_data + offset, msg->topics[i].name, size);
                topics[i].name = topic_data + offset;
                topics[i].len = size;
                topics[i].options = msg->topics[i].options;

                offset += size;
        }

        topic_items = msg->items;

        return 0;
}

static int validate_subscribe(enum m5_pkt_type pkt_type, void *data, void *user)
{
        struct m5_subscribe *msg = (struct m5_subscribe *)data;
        int rc;

        (void)user;
        if (pkt_type != M5_PKT_SUBSCRIBE) {
                return -1;
        }

        rc = fill_topics(msg);
        if (rc != 0) {
                return -1;
        }

        return 0;
}

static int publish(int fd)
{
        struct m5_publish msg = { 0 };
        static int packet_id = 1;
        static int i = -1;
        int rc;

        i = (i + 1) % topic_items;

        msg.payload = (uint8_t *)PUBLISH_PAYLOAD;
        msg.payload_len = strlen(PUBLISH_PAYLOAD);
        msg.topic_name = topics[i].name;
        msg.topic_name_len = topics[i].len;
        msg.qos = topics[i].options & 0x03;
        if (msg.qos != M5_QoS0) {
                msg.packet_id = packet_id;
                packet_id = 1 + packet_id%(MAX_PACKET_ID);
        }

        rc = publish_message(fd, &msg, &loop_forever);
        if (rc != 0) {
                DBG("publish_message");
                return -1;
        }

        return 0;
}

static int publisher_server(void)
{
        uint8_t server_addr[] = LISTEN_ADDR;
        int server_fd;
        int rc;

        rc = tcp_listen(server_addr, LISTEN_PORT, 1, &server_fd);
        if (rc != 0) {
                DBG("tcp_listen");
                goto lb_exit;
        }

        while (loop_forever != 0) {
                struct sockaddr_in client_sa = { 0 };
                int client_fd;

                printf("Waiting for connections [CTRL + C to quit]\n");
                rc = tcp_accept(server_fd, &client_sa, &client_fd);
                if (rc != 0) {
                        continue;
                }

                rc = unpack_msg_reply(client_fd, validate_connect, NULL);
                if (rc != 0) {
                        DBG("unpack_msg_reply CONNECT");
                        goto lb_disconnect_client;
                }

                rc = unpack_msg_reply(client_fd, validate_subscribe, NULL);
                if (rc != 0) {
                        DBG("unpack_msg_reply SUBSCRIBE");
                        goto lb_disconnect_client;
                }

                working_pipe = 1;
                do {
                        rc = publish(client_fd);
                        if (rc != 0) {
                                DBG("publish");
                                goto lb_disconnect_client;
                        }

                        sleep(1);
                } while (loop_forever != 0 && working_pipe == 1);

lb_disconnect_client:
                tcp_disconnect(client_fd);
                printf("Connection closed\n");
        }

        tcp_disconnect(server_fd);
        rc = 0;

lb_exit:
        return rc;

}

static void signal_handler(int id)
{
        if (id == SIGPIPE) {
                working_pipe = 0;
        } else {
                printf("\n\t\tBye!\n\n");
                loop_forever = 0;
        }
}

int main(void)
{
        set_tcp_timeout(60); /* seconds */

        loop_forever = 1;

        signal(SIGPIPE, signal_handler);
        signal(SIGTERM, signal_handler);
        signal(SIGINT, signal_handler);

        return publisher_server();
}

