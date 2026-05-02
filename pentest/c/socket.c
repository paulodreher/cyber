#include <arpa/inet.h>
#include <fcntl.h>
#include <netdb.h>
#include <stdio.h>
#include <sys/socket.h>
#include <unistd.h>

int main(void){

	int mysocket;
	int conn;

	struct sockaddr_in target;

	mysocket = socket(AF_INET,SOCK_STREAM,0);
	target.sin_family = AF_INET;
	target.sin_port = htons(80);
	target.sin_addr.s_addr = inet_addr("192.168.0.1");
	
	conn = connect(mysocket, (struct sockaddr *)&target, sizeof target); 

	if (conn == 0){
		printf("Open port \n");
		close(mysocket);
		close(conn);
	} else{
		printf("Closed port \n");

	}
}	
