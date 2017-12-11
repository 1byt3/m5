# [1byt3](http://1byt3.com)

[![Build Status](https://travis-ci.org/1byt3/m5.svg?branch=dev)](https://travis-ci.org/1byt3/m5)

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

This project provides routines for reading and writing MQTT v5.0
Control Packets.

### Audience

Embedded software engineers that require an MQTT v5.0 implementation
for projects with memory constraints and/or real-time requirements.

### Requirements

For your own projects:

- Any C compiler with support for struct initializers (C99)

To build all the samples and tests:

- GNU/Linux, OpenBSD or FreeBSD operating systems
- Tested on x86 32 and 64 bits
- GCC or CLANG and GNU Make (gmake)

To run the memtest target:

- valgrind (only seems to work fine on GNU/Linux)

### Download

Open a terminal and type:

```
git clone https://github.com/1byt3/m5.git
cd m5
git checkout dev
```

### Build and Run

On GNU/Linux:

```
make && make tests && make memtest
```

On OpenBSD/FreeBSD:

```
gmake && gmake tests
```

See the [samples](samples/) directory for more information
about running the sample applications.

### API usage

See the [samples](samples/) directory, specifically the
[samples_common.c](samples/samples_common.c) file.

### Support

This project is sponsored and supported by [1byt3](http://1byt3.com).

### FAQ

##### Is this project free software?

If you don't receive a commercial license from us (1byt3), you MUST assume that
this software is distributed under the GNU Affero General Public License,
either version 3 of the License, or (at your option) any later version.
See the [LICENSE.txt](LICENSE.txt) file for more information.

Commercial licenses are available, send us an email: customers at 1byt3.com

##### Is this project stable?

This is a pre-alpha release.

##### Is this project compatible with the MQTT 3 or 3.1.1 protocols?

Nope, only version 5 is supported. There are no plans to support older versions
of the MQTT protocol.

### References

OASIS MQTT Version 5 [specification](http://docs.oasis-open.org/mqtt/mqtt/v5.0/)


