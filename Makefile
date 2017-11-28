#
#                                   1byt3
#
#                              License Notice
#
# 1byt3 provides a commercial license agreement for this software. This
# commercial license can be used for development of proprietary/commercial
# software. Under this commercial license you do not need to comply with the
# terms of the GNU Affero General Public License, either version 3 of the
# License, or (at your option) any later version.
#
# If you don't receive a commercial license from us (1byt3), you MUST assume
# that this software is distributed under the GNU Affero General Public
# License, either version 3 of the License, or (at your option) any later
# version.
#
# Contact us for additional information: customers at 1byt3.com
#
#                          End of License Notice
#

#
# MQTT 5 Low Level Packet Library
#
# Copyright (C) 2017 1byt3, customers at 1byt3.com
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as
# published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
#

CFLAGS =				\
	-Wall -Wextra -Werror		\
	-Wno-missing-field-initializers	\
	-Wno-missing-braces		\
	-Wmissing-prototypes		\
	-O0 -g -DM5_USER_PROP_SIZE=2

TESTS =				\
	bin/test_m5		\
	bin/test_corner_cases

VALGRIND = valgrind -q --leak-check=full --error-exitcode=1

all: dirs $(TESTS)

dirs:
	@mkdir -p bin

bin/test_%:		\
	src/test_%.c	\
	src/m5.c	\
	src/m5.h
	$(CC) $(CFLAGS) -Isrc -o $@ $<

tests: $(TESTS)
	@$(foreach test, $(TESTS), $(VALGRIND) ./$(test) || exit 1;)

checkpatch:
	perl ./checkpatch.pl --no-tree -f src/* --ignore BRACES,CONST_STRUCT

clean:
	rm -rf bin

.PHONY: all checkpatch dirs tests clean
