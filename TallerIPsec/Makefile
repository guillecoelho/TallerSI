CC = gcc
CFLAGS   = -w
LDFLAGS = -lgcrypt
OBJFILES = funciones.o ping-sec.o
TARGET   = pingsec

all: $(TARGET)

$(TARGET): $(OBJFILES)
	$(CC) $(CFLAGS) -o $(TARGET) $(OBJFILES) $(LDFLAGS)
	
clean: 
	rm -f $(OBJFILES) $(TARGET) *~