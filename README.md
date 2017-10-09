# [1byt3](http://1byt3.com)

## m5: the MQTT 5 Low Level Packet Library

### What is MQTT?

From the [MQTT version 5 specification](http://docs.oasis-open.org/mqtt/mqtt/v5.0/):

*MQTT is a Client Server publish/subscribe messaging transport protocol.
It is light weight, open, simple, and designed to be easy to implement.
These characteristics make it ideal for use in many situations, including
constrained environments such as for communication in Machine to Machine
(M2M) and Internet of Things (IoT) contexts where a small code footprint
is required and/or network bandwidth is at a premium.*

### Description

This project offers a collection of routines to handle the MQTT version 5
(MQTT5) control packets. With the m5.c/h files, applications trying to implement
an MQTT5 client of server can parse and create all the MQTT5 control packets
defined by the MQTT5 specification.

The m5.c/h files offer basic packing/unpacking functionality to
any C/C++ application trying to implement an MQTT5 Client or Server.

This project does not provide client/server behavior functionality
as described by the MQTT5 specification, section 4 "Operational behavior".

### Design

This project is designed with low-power devices in mind, so it is supposed
to be integrated to applications with constrained resources.

This project does not require a malloc/realloc/calloc/free implementation.

### API usage

See the [m5_test.c](src/m5_test.c) file.

### Build and Run

0. Clone this repository.
1. Edit the Makefile according to the local system configuration.
2. In the repository directory, open a terminal window and type:

    make
3. Run the test application:

    ./bin/m5_test

### FAQ

##### Is this project free software?

If you don't receive a commercial license from us (1byt3), you MUST assume that
this software is distributed under the GNU Affero General Public License,
either version 3 of the License, or (at your option) any later version.
See the LICENSE.txt file for more information.

Commercial licenses are available, send us an email: customers at 1byt3.com

##### Is this project stable?

This is a pre-alpha release.

##### Is this project compatible with the MQTT 3 or 3.1.1 protocols?

Nope, only version 5 is supported. There are no plans to support older versions
of the MQTT protocol.

##### Can the c/h files be integrated in my application/product/service?

Yes, as long as your application/product/service follows the
[GNU Affero General Public License](https://www.gnu.org/licenses/agpl-3.0.en.html).

### References

OASIS MQTT Version 5 [specification](http://docs.oasis-open.org/mqtt/mqtt/v5.0/)
