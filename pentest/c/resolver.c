#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <netdb.h>
#include <arpa/inet.h>

int main(int argc, char *argv[]){
	
	char *target;
	target = argv[1];
	struct hostent *host;
	
	char *result;
	char txt[50];
	FILE *subdomains;
	subdomains = fopen(argv[2],"r");

	if(argc<2){
		printf("|-|-|-|-|-|-|-|-|-|-|-|-|-|-|-|-|-|-|-|-|-|-|-|-|-|-|-|-|-|-|-|-|-|-|-|-|-|-|-|-|-|-|-|\n");
		printf("|-|-|-|-|-|-|-|-| Use mode: ./resolver www.google.com.br  subdomain.txt |-|-|-|-|-|-|-|\n");
		printf("|-|-|-|-|-|-|-|-|-|-|-|-|-|-|-|-|-|-|-|-|-|-|-|-|-|-|-|-|-|-|-|-|-|-|-|-|-|-|-|-|-|-|-|\n");
		return(0);
	} 
	
	while(fscanf(subdomains,"%s", &txt[0]) != EOF){
		result = (char *) strcat(txt,target);
		host = gethostbyname(result);
		if(host == NULL){
			continue;
		}
		
		printf("HOST FOUND: %s ====> ip: %s \n", result, inet_ntoa(*((struct in_addr *)host->h_addr)));
	}
}
