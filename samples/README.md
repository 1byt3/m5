# [1byt3](http://1byt3.com)

## m5 Samples

- [echo server](m5_echo_server.c) A simple MQTT v5.0 echo server,
receives and replies MQTT v5.0 control packets.

- [publisher](m5_publisher.c) A basic MQTT v5.0 publisher application.

- [subscriber](m5_subscriber.c) An application that subscribes to
a given list of topics and waits for incoming PUBLISH control packets.

- [publisher server](m5_publisher_server.c) An application that
receives subscriptions and generates MQTT v5.0 PUBLISH control
packets with different QoS values.

### Requirements

- GNU/Linux, OpenBSD or FreeBSD operating systems
- Tested on x86 32 and 64 bits
- GCC or CLANG and GNU Make (gmake)

### Download

Open a terminal and type:

```
git clone https://github.com/1byt3/m5.git
cd m5
git checkout dev
```

On GNU/Linux:

```
make
```

On OpenBSD/FreeBSD:

```
gmake
```

## echo_server and publisher

### Description

The echo_server waits for connections, receives and processes control
packets and replies with another control packet as indicated by the
MQTT v5.0 specification.

The publisher application sends MQTT v5.0 PUBLISH control packets
with different QoS values.

### Run

Open a terminal window and type:

```
cd m5
./bin/m5_echo_server
```

Open another terminal window and type:

```
cd m5
./bin/m5_publisher
```

The publisher sample output is as follows:

```
Sending: CONNECT
	Client Id: m5_publisher, Keep alive: 0
Received: CONNACK
	Session present: 0, Return code: 0
Sending: PUBLISH
	Topic: greetings, QoS: 00, Packet Id: 0
Sending: PUBLISH
	Topic: greetings, QoS: 01, Packet Id: 1
Received: PUBACK
	Packet Id: 1, Response Code: 0x00
Sending: PUBLISH
	Topic: greetings, QoS: 02, Packet Id: 2
Received: PUBREC
	Packet Id: 2, Response Code: 0x00
Sending: PUBREL
	Packet Id: 2, Response Code: 0x00
Received: PUBCOMP
	Packet Id: 2, Response Code: 0x00
```

echo_server sample output:

```
Received: CONNECT
	Client Id: m5_publisher, Keep alive: 0
Sending: CONNACK
	Session present: 0, Return code: 0
Received: PUBLISH
	Topic: greetings, QoS: 00, Packet Id: 0
Received: PUBLISH
	Topic: greetings, QoS: 01, Packet Id: 1
Sending: PUBACK
	Packet Id: 1, Response Code: 0x00
Received: PUBLISH
	Topic: greetings, QoS: 02, Packet Id: 2
Sending: PUBREC
	Packet Id: 2, Response Code: 0x00
Received: PUBREL
	Packet Id: 2, Response Code: 0x00
Sending: PUBCOMP
	Packet Id: 2, Response Code: 0x00
```

Press CTRL + C to stop any application.

## publisher_server and subscriber

### Description

The publisher server is similar to the publisher application
but it processes the following incoming messages:

- CONNECT and answers with CONNACK
- SUBSCRIBE and replies with SUBACK

Once the CONNECT and SUBSCRIBE handshakes are completed, the
publisher_server application sends PUBLISH control packets with
different QoS values. The subscriber application must reply with
the following packets:

- PUBACK (QoS1)
- PUBREC (QoS2)
- PUBCOMP (QoS2)

### Run

Open a terminal window and type:

```
cd m5
./bin/m5_publisher_server
```

Open another terminal window and type:

```
cd m5
./bin/m5_subscriber
```

The subscriber sample output is:

```
Sending: CONNECT
	Client Id: m5_subscriber, Keep alive: 0
Received: CONNACK
	Session present: 0, Return code: 0
Sending: SUBSCRIBE
	Packet Id: 1, Topics: 3
Received: PUBLISH
	Topic: srv/one, QoS: 01, Packet Id: 1
Sending: PUBACK
	Packet Id: 1, Response Code: 0x00
Received: PUBLISH
	Topic: sensors, QoS: 02, Packet Id: 2
Sending: PUBREC
	Packet Id: 2, Response Code: 0x00
Received: PUBREL
	Packet Id: 2, Response Code: 0x00
Sending: PUBCOMP
	Packet Id: 2, Response Code: 0x00
```

publisher_server sample output:

```
Received: CONNECT
	Client Id: m5_subscriber, Keep alive: 0
Sending: CONNACK
	Session present: 0, Return code: 0
Received: SUBSCRIBE
	Packet Id: 1, Topics: 3
Sending: SUBACK
	Packet Id: 1, Topics: 3
Sending: PUBLISH
	Topic: srv/one, QoS: 01, Packet Id: 1
Received: PUBACK
	Packet Id: 1, Response Code: 0x00
Sending: PUBLISH
	Topic: sensors, QoS: 02, Packet Id: 2
Received: PUBREC
	Packet Id: 2, Response Code: 0x00
Sending: PUBREL
	Packet Id: 2, Response Code: 0x00
Received: PUBCOMP
	Packet Id: 2, Response Code: 0x00
```

Press CTRL + C to stop any application.

