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
CXXFLAGS += -g -O0 -Wall -Wextra
CORE_CXXFLAGS = $(filter-out -std=%,$(CXXFLAGS)) -std=c++98
WEB_CXXFLAGS = $(filter-out -std=%,$(CXXFLAGS)) -std=c++11
WEB_CPPFLAGS = $(CPPFLAGS) -isystem third_party/cpp-httplib
LDFLAGS  += -L$(LIBCRYPTOSEC_LIBDIR) -L$(OPENSSL_LIBDIR) \
            -Wl,-rpath,$(LIBCRYPTOSEC_LIBDIR) -Wl,-rpath,$(OPENSSL_LIBDIR)
LDLIBS   += -lcryptosec -lcrypto -pthread

CORE_SOURCES := $(wildcard src/agreement/*.cpp src/operator/*.cpp src/file_io/*.cpp) src/service/signature_service.cpp
CORE_OBJECTS := $(patsubst %.cpp,$(BUILD_DIR)/%.o,$(CORE_SOURCES))
CORE_LIBRARY := $(BUILD_DIR)/libmsp-core.a
WEB_SOURCES := web_main.cpp $(wildcard src/controller/*.cpp src/repository/*.cpp) \
               src/service/auth_service.cpp src/service/local_signature_service.cpp
WEB_OBJECTS := $(patsubst %.cpp,$(BUILD_DIR)/%.o,$(WEB_SOURCES))
TEST_OBJECTS := $(BUILD_DIR)/tests/service_tests.o $(BUILD_DIR)/tests/web_tests.o
DEPS := $(CORE_OBJECTS:.o=.d) $(WEB_OBJECTS:.o=.d) $(BUILD_DIR)/main.d $(TEST_OBJECTS:.o=.d)

.PHONY: all build web run test test-web clean help msp-cli msp-web
all: build
build: $(TARGET)
web msp-web: $(BUILD_DIR)/msp-web
msp-cli: $(BUILD_DIR)/msp-cli

$(CORE_LIBRARY): $(CORE_OBJECTS)
	$(AR) rcs $@ $^

$(TARGET): $(BUILD_DIR)/main.o $(CORE_LIBRARY)
	$(CXX) $(LDFLAGS) -o $@ $^ $(LDLIBS)

$(BUILD_DIR)/msp-cli: $(TARGET)
	ln -sf pam $@

$(BUILD_DIR)/msp-web: $(WEB_OBJECTS) $(CORE_LIBRARY)
	$(CXX) $(LDFLAGS) -o $@ $^ $(LDLIBS)

$(CORE_OBJECTS) $(BUILD_DIR)/main.o: $(BUILD_DIR)/%.o: %.cpp
	@mkdir -p $(dir $@)
	$(CXX) $(CPPFLAGS) $(CORE_CXXFLAGS) -MMD -MP -c $< -o $@

$(WEB_OBJECTS) $(TEST_OBJECTS): $(BUILD_DIR)/%.o: %.cpp
	@mkdir -p $(dir $@)
	$(CXX) $(WEB_CPPFLAGS) $(WEB_CXXFLAGS) -MMD -MP -c $< -o $@

$(BUILD_DIR)/service-tests: $(BUILD_DIR)/tests/service_tests.o \
    $(BUILD_DIR)/src/service/auth_service.o $(BUILD_DIR)/src/service/local_signature_service.o \
    $(BUILD_DIR)/src/repository/user_repository.o $(CORE_LIBRARY)
	$(CXX) $(LDFLAGS) -o $@ $^ $(LDLIBS)

$(BUILD_DIR)/web-tests: $(BUILD_DIR)/tests/web_tests.o
	$(CXX) $(LDFLAGS) -o $@ $^ -pthread

test-web: $(BUILD_DIR)/msp-web $(BUILD_DIR)/service-tests $(BUILD_DIR)/web-tests
	./$(BUILD_DIR)/service-tests
	sh tests/run_web_tests.sh ./$(BUILD_DIR)/msp-web ./$(BUILD_DIR)/web-tests

run: $(TARGET)
	./$(TARGET) --help

test: $(TARGET)
	sh tests/run_tests.sh ./$(TARGET)

clean:
	rm -rf $(BUILD_DIR)

help:
	@printf '%s\n' \
	  'make build  - compile the application' \
		  'make web    - compile the local HTTP interface (C++11)' \
	  'make test-web - test services and HTTP routes' \
	  'make run    - show the application usage' \
		  'make test   - run the end-to-end challenge scenarios' \
	  'make clean  - remove generated build files'

-include $(DEPS)
