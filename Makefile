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

M5_SRC = src
TEST_SRC = tests

INCLUDES = -I$(M5_SRC) -I$(TEST_SRC)

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

bin/test_%:			\
	$(TEST_SRC)/test_%.c	\
	$(M5_SRC)/m5.c		\
	$(M5_SRC)/m5.h
	$(CC) $(CFLAGS) $(INCLUDES) -o $@ $<

tests: $(TESTS) dirs
	@$(foreach test, $(TESTS), ./$(test) || exit 1;)

memtest: $(TESTS)
	@$(foreach test, $(TESTS), $(VALGRIND) ./$(test) || exit 1;)

checkpatch:
	@git --no-pager diff HEAD~ HEAD | perl ./checkpatch.pl -q --no-tree --ignore BRACES,FILE_PATH_CHANGES,CONST_STRUCT -

clean:
	rm -f bin/*

.PHONY: all dirs tests memtest checkpatch clean
