all:
		gcc jail.c -o jail
		gcc -shared libjail.c -o libjail.so -lrt -fPIC
clean:
	rm -rf jail
	rm -rf libjail.so
