LDLIBS=-lpcap -lpthread

all: deauth-attack

deauth-attack: main.o
	$(LINK.cc) $^ $(LOADLIBES) $(LDLIBS) -o $@
	rm -f *.o

clean:
	rm -f deauth-attack *.o
