APP_DIR=./apps
webserver: $(APP_DIR)/webserver.c libuv/.libs/libuv.a libhttp_parser/http_parser.o libjason_parser/jsmn.o
#	gcc -DEV_MULTIPLICITY=0  -o webserver $(APP_DIR)/webserver.c libuv/.libs/libuv.a -lpthread
#	gcc -o webserver $(APP_DIR)/webserver.c libuv/.libs/libuv.a libhttp_parser/libhttp_parser.a  -lpthread
	gcc -o webserver $(APP_DIR)/webserver.c libuv/.libs/libuv.a libhttp_parser/http_parser.o libjason_parser/jsmn.o -lpthread  

libuv/.libs/libuv.a: 
	$(MAKE) -C libuv 

libhttp_parser/libhttp_paraser.a:
	$(MAKE) -C libhttp_parser pacakge

libjason_parser/jsmn.o:
	$(MAKE) -C libjason_parser jsmn.o

clean:
	$(MAKE) -C libuv clean
	$(MAKE) -C libhttp_parser clean
	$(MAKE) -C libjason_parser clean
	rm webserver
	
