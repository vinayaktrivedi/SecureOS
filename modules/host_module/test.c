#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include<stdio.h>
int main(){
//char *value = "ls";
int pid = fork();
if(pid == 0){
char *line[] = { "ssh", "vinayakt@vyom.cc.iitk.ac.in", 0 };

execvp(line[0], line);
}
return 0;
}
