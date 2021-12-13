/**
 * @file part_a.cpp
 * @author Elif Kızılkaya
 
 * @brief Code for part A for the project EXPLAIN
 *
 *
 * EXPLANATION
 * How to compile and run:
    make
    ./part_a.out blackbox part_a_output.txt
 */


#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <string.h>
#include <cstdio>
#include <iostream>
#include <sys/wait.h>
#include <signal.h>
#include <fcntl.h>
#include <sys/stat.h>

using namespace std;

#define CREATE_FLAGS (O_WRONLY | O_CREAT | O_APPEND)
#define CREATE_MODE (S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH)

int main(int argc, char *argv[]) {
    /**
     * p2c and c2p are the pipe handles for the parent-to-child and child-to-parent pipes.
     */
    int     p2c[2], c2p[2], nbytes;
    pid_t   pid;
    char w_buffer[1000], r_buffer[10000];

    if (argc != 3){   /* checking for valid command-line arguments */  
        fprintf(stderr, "Invalid command\n");
        return 1; 
   }     

    /**
     * The parent creates both pipes, which will be shared between the parent and the child.
     */
    pipe(p2c);
    pipe(c2p);

    if((pid=fork()) == -1) {
        fprintf(stderr, "fork() failed.\n");
        exit(-1);
    }

    //.......................................................................................................
    if(pid > 0) {
        /**
         * This is the code for the parent process.
         */

        /**
         * The parent should close the ends of the pipes that it will not use.
         */
        close(p2c[0]);    // Parent will not read from p2c
        close(c2p[1]);    // Parent will not write to c2p      


        int input1; 
        int input2; //Inputs taken from stdin
        scanf("%d %d", &input1, &input2);
        
        /**
         * Send a request message to the child process.
         * Don't forget to add "1" to the length of the string for the NULL character.
         */

        char buf1[256];

        sprintf(buf1, "%d %d", input1, input2);
        write(p2c[1], buf1, (strlen(buf1) + 1));
        
        /**
         * Now, wait for the response of the child.
         */
       
        /**
         * We will not bother for waiting for the child (no need to worry if the parent 
         * dies before the child responds) since the parent cannot terminate before 
         * the child process sends the response (due to the read() function call.
         */

        int fd;

        fd = open(argv[2], CREATE_FLAGS, CREATE_MODE);
        if (fd == -1) {
            perror("Failed to open output gile");
            return 1;
        }
        if (dup2(fd, STDOUT_FILENO) == -1) {
            perror("Failed to redirect standard output");
            return 1;
        }
        if (close(fd) == -1) {
            perror("Failed to close the file");
            return 1;
        }
        
        memset(r_buffer, 0, 10000);
        nbytes = read(c2p[0], r_buffer, sizeof(r_buffer));
        

        /* This part is checking whether the output is error or integer
            If it is integer, then converting to int and then converting
            to string would not effect the size. However, converting a text
            to int would make the size of the r_buffer 1 because of the end
            of the string. That is why, 1 is added in the if condition.
        */
       
        /* I utilized from an idea from this forum:
        https://stackoverflow.com/questions/16644906/how-to-check-if-a-string-is-a-number
        */
        char text[10000];
        sprintf(text, "%lu", atol(r_buffer));

        if (strlen(r_buffer) == (strlen(text) + 1)) {
             printf("SUCCESS:\n%s", r_buffer);
        }
        else {

             printf("FAIL:\n%s", r_buffer);
        }
    
    }
    //.......................................................................................................
    else {
        /**
         * This is the code for the child process.
         */

        /**
         * The child should close the ends of the pipes that it will not use.
         */
        char* path = argv[1]; //Path of the binary file blackbox

        /**
         * Wait for the request from the parent.
         */
       
        dup2(p2c[0], STDIN_FILENO);
        dup2(c2p[1], STDOUT_FILENO);
        dup2(c2p[1], STDERR_FILENO);

    
        /**
         * The child can close all pipes since they are not needed anymore. Nothing will happen to stdin, stdout, stderr.
         */
        close(c2p[0]);
        close(c2p[1]);
        close(p2c[0]);
        close(p2c[1]);

        execl(path, "./blackbox", NULL);    
    }

    return(0);
}

