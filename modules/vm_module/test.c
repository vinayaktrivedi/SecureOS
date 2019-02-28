#include<stdio.h> 
#include<sys/wait.h> 
#include<unistd.h>
#include<stdlib.h>

int main(){
	char ssh_arg[256];	
	printf("user_exec_agent"); //this printf tells kernel module to note this process as user_exec_agent
	printf("user\n"); //this printf tells kernel module to note this process as user_exec_agent
	
	
	return 0;
}