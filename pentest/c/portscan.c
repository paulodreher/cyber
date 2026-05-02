#include <arpa/inet.h>
#include <fcntl.h>
#include <netdb.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/socket.h>
#include <unistd.h>
#include <fcntl.h>

int main(int argc, char *argv[]){

	int mysocket;
	int conn;
	int port;
	int iniport = 0;
	int endport = 65535;
	char *ip = argv[1];
	struct sockaddr_in target;

	for(port=iniport; port<endport; port++){
		mysocket = socket(AF_INET,SOCK_STREAM,0);
		target.sin_family = AF_INET;
		target.sin_port = htons(port);
		target.sin_addr.s_addr = inet_addr(ip);
	
		conn = connect(mysocket, (struct sockaddr *)&target, sizeof target); 

		if (conn == 0){
			printf("Port %d - [OPEN] \n",port);
			close(mysocket);
			close(conn);
		} else{
			close(mysocket);
			close(conn);
		}
	}
}	
