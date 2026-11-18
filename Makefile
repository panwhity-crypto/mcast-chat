# 带文件传输功能的多播聊天工具 —— 构建脚本
#
#   make            编译图形界面版 mcastchat（含 --cli 命令行模式）
#   make cli        只编译命令行版 mcastchat-cli（不需要 GTK）
#   make test       编译并运行单元测试与多节点集成测试
#   make asan       用 AddressSanitizer 编译测试并运行（检查内存错误）
#   make clean

CC      ?= gcc
CFLAGS  ?= -O2 -g
CFLAGS  += -std=c11 -D_GNU_SOURCE -Wall -Wextra -Wno-unused-parameter -pthread
SSL_CFLAGS := $(shell pkg-config --cflags openssl)
SSL_LIBS   := $(shell pkg-config --libs openssl)
GTK_CFLAGS := $(shell pkg-config --cflags gtk+-3.0 2>/dev/null)
GTK_LIBS   := $(shell pkg-config --libs gtk+-3.0 2>/dev/null)

CORE = src/protocol.c src/crypto.c src/net.c src/members.c src/filexfer.c src/node.c
CORE_OBJ = $(CORE:src/%.c=build/%.o)

.PHONY: all cli test asan clean

all: mcastchat

build/%.o: src/%.c src/*.h | build
	$(CC) $(CFLAGS) $(SSL_CFLAGS) -c $< -o $@

build/gui.o: src/gui.c src/*.h | build
	$(CC) $(CFLAGS) $(SSL_CFLAGS) $(GTK_CFLAGS) -c $< -o $@

build/main_gtk.o: src/main.c src/*.h | build
	$(CC) $(CFLAGS) $(SSL_CFLAGS) $(GTK_CFLAGS) -DHAVE_GTK -c $< -o $@

build:
	mkdir -p build

mcastchat: $(CORE_OBJ) build/cli.o build/gui.o build/main_gtk.o
	$(CC) $(CFLAGS) $^ -o $@ $(SSL_LIBS) $(GTK_LIBS)

mcastchat-cli: $(CORE_OBJ) build/cli.o build/main.o
	$(CC) $(CFLAGS) $^ -o $@ $(SSL_LIBS)

cli: mcastchat-cli

build/test_unit: tests/test_unit.c $(CORE) src/*.h | build
	$(CC) $(CFLAGS) $(SSL_CFLAGS) -Isrc tests/test_unit.c $(CORE) -o $@ $(SSL_LIBS)

build/test_node: tests/test_node.c $(CORE) src/*.h | build
	$(CC) $(CFLAGS) $(SSL_CFLAGS) -Isrc tests/test_node.c $(CORE) -o $@ $(SSL_LIBS)

test: build/test_unit build/test_node
	./build/test_unit
	./build/test_node

asan:
	$(MAKE) clean-tests
	$(MAKE) test CFLAGS="-O1 -g -fsanitize=address,undefined -fno-omit-frame-pointer"

clean-tests:
	rm -f build/test_unit build/test_node

clean:
	rm -rf build mcastchat mcastchat-cli

build/gui_demo: tests/gui_demo.c $(CORE_OBJ) build/gui.o | build
	$(CC) $(CFLAGS) $(SSL_CFLAGS) $(GTK_CFLAGS) -Isrc tests/gui_demo.c $(CORE_OBJ) build/gui.o -o $@ $(SSL_LIBS) $(GTK_LIBS) -lm

screenshots: build/gui_demo
	mkdir -p docs/screenshots
	GTK_CSD=0 xvfb-run -a -s "-screen 0 3100x720x24" ./build/gui_demo docs/screenshots
