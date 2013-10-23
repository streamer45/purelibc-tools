all: 
	gcc direwrite.c -o direwrite -lrt
	gcc -shared libdirewrite.c -o libdirewrite.so -lrt -fPIC
clean:
	rm -rf direwrite 
	rm -rf libdirewrite.so
