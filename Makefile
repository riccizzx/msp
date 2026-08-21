# Build and test the PAM prototype.
#
# Override dependency locations when they are not installed in the defaults:
#   make OPENSSL_PREFIX=/path/to/openssl LIBCRYPTOSEC_PREFIX=/path/to/libcryptosec

TARGET       := build/pam
BUILD_DIR    := build
CXX          ?= g++

OPENSSL_PREFIX       ?= /usr/local/ssl
OPENSSL_LIBDIR       ?= $(OPENSSL_PREFIX)/lib
OPENSSL_INCLUDEDIR   ?= $(OPENSSL_PREFIX)/include
LIBCRYPTOSEC_PREFIX  ?= /usr/local
LIBCRYPTOSEC_LIBDIR  ?= $(LIBCRYPTOSEC_PREFIX)/lib64
LIBCRYPTOSEC_INCLUDE ?= $(LIBCRYPTOSEC_PREFIX)/include
LIBP11_PREFIX        ?= /opt/libp11
LIBP11_INCLUDEDIR    ?= $(LIBP11_PREFIX)/include

CPPFLAGS += -I. -I$(OPENSSL_INCLUDEDIR) -I$(LIBCRYPTOSEC_INCLUDE) -I$(LIBP11_INCLUDEDIR) -DFIPS
CXXFLAGS += -std=c++98 -g -O0 -Wall -Wextra
LDFLAGS  += -L$(LIBCRYPTOSEC_LIBDIR) -L$(OPENSSL_LIBDIR) \
            -Wl,-rpath,$(LIBCRYPTOSEC_LIBDIR) -Wl,-rpath,$(OPENSSL_LIBDIR)
LDLIBS   += -lcryptosec -lcrypto -pthread

SOURCES := main.cpp $(shell find src -type f -name '*.cpp' | sort)
OBJECTS := $(patsubst %.cpp,$(BUILD_DIR)/%.o,$(SOURCES))
DEPS    := $(OBJECTS:.o=.d)

.PHONY: all build run test clean help

all: build

build: $(TARGET)

$(TARGET): $(OBJECTS)
	@mkdir -p $(dir $@)
	$(CXX) $(LDFLAGS) -o $@ $^ $(LDLIBS)

$(BUILD_DIR)/%.o: %.cpp
	@mkdir -p $(dir $@)
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) -MMD -MP -c $< -o $@

run: $(TARGET)
	./$(TARGET) --help

test: $(TARGET)
	sh tests/run_tests.sh ./$(TARGET)

clean:
	rm -rf $(BUILD_DIR)

help:
	@printf '%s\n' \
	  'make build  - compile the application' \
		  'make run    - show the application usage' \
		  'make test   - run the end-to-end challenge scenarios' \
	  'make clean  - remove generated build files'

-include $(DEPS)
