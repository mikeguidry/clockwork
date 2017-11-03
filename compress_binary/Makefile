trace:
	rm -f trace
	gcc -o trace trace.c x86_emulate.c -I__i386__
mini_trace:
	gcc -o mini_trace mini_trace.cpp

all: mini_trace trace
