INC=/usr/local/ssl/include/
LIB=/usr/local/ssl/lib/

all:
	
	gcc -I$(INC) -L$(LIB) tunproxy.c -o tunproxy -lssl -lcrypto -ldl -fpermissive
	gcc -I$(INC) -L$(LIB) generatePassword.c -o generatePassword -lssl -lcrypto -ldl -fpermissive
	

clean:
	rm -rf *~ tunproxy
