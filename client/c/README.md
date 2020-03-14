Compile:
1. cd to repository's directory ; reach client directory
2. cd c for c-lang based client, which uses python+gmail for email.
4. make 
5. (This will generate client.o in current directory)

Run:
1. sudo ./client.o PROXY_IP 443 URL TIMEOUT
2. Example : sudo ./client.o 192.168.2.5 443 https://localhost/100M 40
