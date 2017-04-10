APP_DIR=./apps
webserver: $(APP_DIR)/webserver.c libuv/.libs/libuv.a
#	gcc -DEV_MULTIPLICITY=0  -o webserver $(APP_DIR)/webserver.c libuv/.libs/libuv.a -lpthread
	gcc -o webserver $(APP_DIR)/webserver.c libuv/.libs/libuv.a -lpthread

libuv/.libs/libuv.a: 
	$(MAKE) -C libuv 


clean:
	$(MAKE) -C libuv clean
	rm webserver
	
