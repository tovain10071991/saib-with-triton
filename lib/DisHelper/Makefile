ROOT_DIR = ../..
OBJ_DIR = .

include $(ROOT_DIR)/Makefile.common

CXXFLAGS += -I$(UDIS86_INCLUDE_DIR)

LIB = $(OBJ_DIR)/DisHelper.a
SOURCE = $(wildcard *.cpp)
OBJECT := $(OBJ_DIR)/$(SOURCE:.cpp=.o)

default: $(LIB)

$(LIB): $(OBJECT)
	$(AR) crv $(LIB) $(OBJECT)

$(OBJECT): $(SOURCE)

clean:
	rm -rf *.o *.a