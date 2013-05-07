#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stdbool.h>
#include <unistd.h>

#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>

#include <string.h>

#define DEBUG 1

void fail(const char *, ...);
void prt(const char *, ...);
void fprt(FILE *, const char *, ...);

void help(){
	prt("Commands: [cmd] [argument] ... \n");
	prt(" help : shows this message\n");
	prt(" quit : quits\n");
	prt(" version : sends version message client\n");
	prt(" ping : sends ping message to connected client\n");
	prt("\n");
}

int command(){
	// Read a line
	char *line = 0;
	unsigned int len = 0;
	getline(&line, &len, stdin);
	char cmd[64] = {0}; // this will crash if you enter bad strings in stdin!
	sscanf(line, " %s ", cmd);

	// Main interactive command dispatch
	if (!strcmp(cmd, "ping")) {
		prt("You said ping\n");
	} else if (!strcmp(cmd, "help")) {
		help();
	} else if (!strcmp(cmd, "version")) {
		prt("Sending version\n");
	} else if (!strcmp(cmd, "quit")) {
		prt("Quitting...\n");
		return 0;
	} else if (!strcmp(cmd, "")) {
	} else {
		prt("Command not recognized: '%s'\n", cmd);
	}
	
	return 1; // rolling along
}

int main(int argc, char *argv[]){
	prt("CMSC417: Rudimentary bitcoin client.\n");
	prt("Andrew Badger, Thach Hoang. 2013.\n");
	help();
	
	fd_set rfds;
	struct timeval tv;
	int retval;
	bool running = true;

	while (running) {
		/* Watch stdin (fd 0) to see when it has input. */
		FD_ZERO(&rfds);
		FD_SET(STDIN_FILENO, &rfds);

		/* Wait up to five seconds. */
		tv.tv_sec = 5;
		tv.tv_usec = 0;

		retval = select(1, &rfds, NULL, NULL, &tv);

		if (retval == -1) {
			perror("select()");
		} else if (retval) {
			if (FD_ISSET(STDIN_FILENO, &rfds))
				if (!command())
					running = false;
		} else {
			// nothing
		}
	}
	
	return 0;
}

/* Debugging */

void fail(const char *fmt, ...) {
	va_list args;
	va_start(args, fmt);
	vfprintf(stderr, fmt, args);
	va_end(args);
	exit(EXIT_FAILURE);
}

void prt(const char* fmt, ...){
	if(!DEBUG)
		return;
	va_list args;
	va_start(args, fmt);
	vprintf(fmt, args);
	va_end(args);
}

void fprt(FILE *stream, const char* fmt, ...){
	if(!DEBUG)
		return;
	va_list args;
	va_start(args, fmt);
	vfprintf(stream, fmt, args);
	va_end(args);
}

