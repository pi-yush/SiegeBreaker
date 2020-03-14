
center: center.c custom_parser.h custom_string_manager.h custom_base64.h struct_file.h
	gcc center.c  -lpcap -lssl -lcrypto -lpthread -lm -o center.o -I /opt/openssl/1.1.1-dev/include/ -L /opt/openssl/1.1.1-dev/lib/

single_conn: single_conn.c custom_parser.h custom_string_manager.h  struct_file.h
	gcc single_conn.c  -lpcap -lssl -lcrypto -lpthread -lm -o single_conn.o -I /opt/openssl/1.1.1-dev/include/ -L /opt/openssl/1.1.1-dev/lib/



