CC = gcc

# Add paths to the library's headers
CFLAGS = -I../src/inc/api -I../src/inc/internal -I../src/common/inc -I../src/hal/inc

# Add path to the library's build output
LDFLAGS = -L../src

# Link against the lib60870 library and system libraries
LDLIBS = -l60870 -lpthread

# --- Unity Test Framework ---
UNITY_PATH = ./unity
UNITY_SRC = $(UNITY_PATH)/src/unity.c
CFLAGS += -I$(UNITY_PATH)/src

# --- Source and Object Files ---
TARGET = all_tests
SRC = all_tests.c
OBJS = $(SRC:.c=.o)

.PHONY: all clean run

all: $(TARGET)

$(TARGET): $(OBJS) $(UNITY_PATH)/src/unity.o
	$(CC) $(LDFLAGS) -o $@ $^ $(LDLIBS)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

$(UNITY_PATH)/src/unity.o: $(UNITY_PATH)/src/unity.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(TARGET) $(OBJS) $(UNITY_PATH)/src/unity.o

run: all
	./$(TARGET)