all: 
	gcc puretrace.c -o puretrace -lrt
	gcc -shared syscall_info.c libpuretrace.c -o libpuretrace.so -lrt -fPIC
	gcc sys_switch_gen.c -o ss_gen -g
clean:
	rm -rf libpuretrace.so
	rm -rf puretrace
	rm -rf ss_gen
