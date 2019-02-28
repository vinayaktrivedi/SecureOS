#include<stdio.h> 
#include<sys/wait.h> 
#include<unistd.h>
#include<stdlib.h>

int main(){
	char ssh_arg[256];	
	printf("user_exec_agent"); //this printf tells kernel module to note this process as user_exec_agent
	while(1){
		scanf( "%s" , ssh_arg ); //this function is hooked inside kernel for this process and ssh arguemnt comes from host.
	
		if (fork() == 0){
			printf( "%s\n" , ssh_arg );
			printf("user_exec_agent_child");  //this printf tells kernel module to note this process pid as child of exec_user_agent
	      	char * argv_list[] = {"ssh",ssh_arg,NULL}; 
		    execvp("ssh",argv_list); 
		    exit(0); 
	   	}
	}
	return 0;
}