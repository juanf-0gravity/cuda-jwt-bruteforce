# Makefile for JWT CUDA Bruteforcer

# Compiler settings
NVCC = nvcc
CC = gcc
CUDA_PATH ?= /usr/local/cuda

# Flags
NVCC_FLAGS = -O3 -arch=sm_75 -std=c++11
INCLUDES = -I$(CUDA_PATH)/include
LIBS = -L$(CUDA_PATH)/lib64 -lcudart

# Target executable
TARGET = jwt_bruteforce

# Source files
SOURCES = jwt_bruteforce.cu

# Default target
all: $(TARGET)

# Build the executable
$(TARGET): $(SOURCES)
	$(NVCC) $(NVCC_FLAGS) $(INCLUDES) $(SOURCES) -o $(TARGET) $(LIBS)

# Clean build artifacts
clean:
	rm -f $(TARGET) *.o

# Run with example JWT
test:
	./$(TARGET) -t "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c" -v

# Install (optional)
install: $(TARGET)
	cp $(TARGET) /usr/local/bin/

# Help
help:
	@echo "JWT CUDA Bruteforcer Makefile"
	@echo "=============================="
	@echo "Targets:"
	@echo "  all     - Build the executable (default)"
	@echo "  clean   - Remove build artifacts"
	@echo "  test    - Run with example JWT token"
	@echo "  install - Install to /usr/local/bin"
	@echo "  help    - Show this help message"
	@echo ""
	@echo "Usage:"
	@echo "  make          - Build the project"
	@echo "  make clean    - Clean build files"
	@echo "  make test     - Run test with sample JWT"

.PHONY: all clean test install help