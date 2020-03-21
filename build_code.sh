#Build Client
cd main
cd ./client/c
make
#Build proxy
cd ../../
cd ./proxy/
make center
make single_conn
cd ../
#