all: 
		gcc curl_test.c -o curl_test -lcurl
		gcc -shared libcathttp.c -o libcathttp.so -lcurl -lrt -fPIC
clean:
	rm -rf libcathttp.so
