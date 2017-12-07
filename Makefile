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

VALGRIND = valgrind -q --leak-check=full --error-exitcode=1

SAMPLES_CFLAGS += -DM5_SKIP_ON_FULL_USER_PROP=1
CFLAGS +=				\
	-Wall -Wextra -Werror		\
	-Wno-missing-field-initializers	\
	-Wno-missing-braces		\
	-Wmissing-prototypes		\
	-O0 -g

PROJECT_DIR = $(CURDIR)
M5_SRC = $(PROJECT_DIR)/src
M5_INC = -I$(M5_SRC)

SAMPLES_DIR = $(PROJECT_DIR)/samples
TESTS_DIR = $(PROJECT_DIR)/tests
OBJS_DIR = $(PROJECT_DIR)/obj
BINS_DIR = $(PROJECT_DIR)/bin

M5_OBJ = $(OBJS_DIR)/m5.o

export

all: dirs $(M5_OBJ) build_tests build_samples

dirs:
	@mkdir -p $(BINS_DIR)
	@mkdir -p $(OBJS_DIR)

$(M5_OBJ):		\
	$(M5_SRC)/m5.c	\
	$(M5_SRC)/m5.h
	$(CC) $(CLAGS) $(M5_INC) -c -o $@ $<

build_tests:
	cd $(TESTS_DIR) && $(MAKE)

build_samples:
	cd $(SAMPLES_DIR)  && $(MAKE)

tests:
	cd $(TESTS_DIR) && $(MAKE) tests

memtest:
	cd $(TESTS_DIR) && $(MAKE) memtest

checkpatch:
	@git --no-pager diff HEAD~ HEAD | perl ./checkpatch.pl -q --no-tree --ignore BRACES,FILE_PATH_CHANGES,CONST_STRUCT,MACRO_WITH_FLOW_CONTROL -

clean:
	@rm -f bin/*
	@rm -f obj/*

.PHONY: all dirs build_tests build_samples tests memtest checkpatch clean
