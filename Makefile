






all:
	gcc -g proxy.c net.c cJSON.c -o proxy -pthread  -lm
