all:
		gcc direwrite.c -o direwrite
		gcc jail.c -o jail
		gcc -shared libjail.c -o libjail.so -lrt -fPIC
		gcc -shared libdirewrite.c -o libdirewrite.so -lrt -fPIC
