APP_DIR=./apps
webserver: $(APP_DIR)/webserver.c libuv/.libs/libuv.a libhttp_parser/http_parser.o
#	gcc -DEV_MULTIPLICITY=0  -o webserver $(APP_DIR)/webserver.c libuv/.libs/libuv.a -lpthread
#	gcc -o webserver $(APP_DIR)/webserver.c libuv/.libs/libuv.a libhttp_parser/libhttp_parser.a  -lpthread
	gcc -o webserver $(APP_DIR)/webserver.c libuv/.libs/libuv.a libhttp_parser/http_parser.o  -lpthread  

libuv/.libs/libuv.a: 
	$(MAKE) -C libuv 

#libhttp_parser/libhttp_paraser.a 
#	$(MAKE) -C libhttp_parser pacakge
#
libhttp_parser/http_parser.o:
	$(MAKE) -C http_parser.o 



clean:
	$(MAKE) -C libuv clean
	$(MAKE) -C libhttp_parser clean
	rm webserver
	
