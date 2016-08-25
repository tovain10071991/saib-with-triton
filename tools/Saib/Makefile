ROOT_DIR = ../..
OBJ_DIR = .
BIN_DIR = $(ROOT_DIR)/bin

include $(ROOT_DIR)/Makefile.common

EXECUTABLE = $(BIN_DIR)/saib
SOURCE = $(wildcard *.cpp)
OBJECT := $(OBJ_DIR)/$(SOURCE:.cpp=.o)
LIBS = $(wildcard $(ROOT_DIR)/lib/*/*.a) $(ROOT_DIR)/lib/protobufHelper/protobufHelper.a $(ROOT_DIR)/lib/Common/SaibCommon.a

default: $(EXECUTABLE)

$(EXECUTABLE): $(OBJECT)
	$(CXX) -o $(EXECUTABLE) $(OBJECT) $(LIBS) $(LDFLAGS)