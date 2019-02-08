#include <stdio.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <string.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <unistd.h>

int main() {
	int fd;
	struct sockaddr_un addr;
	int ret;
	char buff[8192];
	struct sockaddr_un from;
	int ok = 1;
	int len;

	if ((fd = socket(AF_UNIX, SOCK_STREAM, 0)) < 0) {
		perror("socket");
		ok = 0;
	}

	if (ok) {
		memset(&addr, 0, sizeof(addr));
		addr.sun_family = AF_UNIX;
		strcpy(addr.sun_path, "/tmp/foo");
		if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) == -1) {
			perror("connect");
			ok = 0;
		}
	}

	// if (ok) {
	// 	strcpy (buff, "iccExchangeAPDU");
	// 	if (send(fd, buff, strlen(buff)+1, 0) == -1) {
	// 		perror("send");
	// 		ok = 0;
	// 	}
	// 	printf ("sent iccExchangeAPDU\n");
	// }

	while(1){
			if (ok) {
			if ((len = recv(fd, buff, 8192, 0)) < 0) {
				perror("recv");
				ok = 0;
			}
			printf ("%s\n", len, buff);
		}	
	}
	

	if (fd >= 0) {
		close(fd);
	}

	//unlink (CLIENT_SOCK_FILE);
	return 0;
}

