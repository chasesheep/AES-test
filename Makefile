.PHONY: all clean
all: AES.exe SHA.exe
AES.exe: AES.cpp AES.h
	g++ AES.cpp -O2 -msse -o AES.exe
SHA.exe: sha.cpp sha.h
	g++ sha.cpp -O2 -msse -o SHA.exe

clean:
	del *.o *.exe