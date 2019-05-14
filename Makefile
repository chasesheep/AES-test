.PHONY: all clean
all: AES.exe
AES.exe: AES.cpp AES.h
	g++ AES.cpp -O2 -msse -o AES.exe
clean:
	del *.o *.exe