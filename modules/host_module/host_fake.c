#include<stdio.h> 
#include<string.h>
#include <unistd.h>
#include<stdio.h>
#include<stdlib.h>
#include <fcntl.h> 
int main(){
	char file[128] = "/home/";
    char arg[64];
    printf("Please enter the name of secret file you want\n");
    scanf("%s",arg);
    strcat(file,arg);
    int fd = open(file, O_RDWR|O_CREAT,0666);
        if(fd < 0)
                 exit(-1);

    printf("Please enter the message you want to put\n");
    scanf("%s",arg);
    write(fd,arg,strlen(arg));
    printf("Thanks for using the app\n");
    close(fd);
    return 0;
}