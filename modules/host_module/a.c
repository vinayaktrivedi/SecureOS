#include<stdio.h> 
#include<string.h>
#include <unistd.h>
#include<stdio.h>
int main(){
        char ar[32];
        char *rootid = "8d42c43449108789f51476ac8a0d386334cae1360fa9f9c3377073e8e4792653\n";
        char *childid = "c6235874094907ec06e1d8474926a23190026126d9c175e7f6b07bdc206e8df9\n";
        //char ssh_arg[256];    
        int fd = open("/tmp/sandbox.log", O_RDWR);
        if(fd < 0)
                 exit(-1);
        
        write(fd, rootid, strlen(rootid));
        while(1){

        //scanf( "%s" , ar);
                sleep(20);
        int pid = fork();
        if(pid==0){
                write(fd, childid, strlen(childid));                
                char *line[] = { "ssh", "vinayakt@turing.cse.iitk.ac.in", 0 };
                execvp(line[0], line);
        }
}
        return 0;
}

