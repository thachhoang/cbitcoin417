#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stdbool.h>
#include <unistd.h>

#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <string.h>

#include <CBAssociativeArray.h>
#include <CBByteArray.h>
#include <CBConstants.h>
#include <CBNetworkAddress.h>
#include <CBPeer.h>

#define DEBUG 1

void fail(const char *, ...);	// exit in failure with custom message
void sysfail(const char *);		// perror wrapper
void prt(const char *, ...);	// printf wrapper
void deb(const char *, ...);	// printf only in debug mode

//#define NETMAGIC 0xffffffff // mainnet
//#define NETMAGIC 0x0709110B // testnet
#define NETMAGIC 0xd0b4bef9 // umdnet

#define DEFAULT_IP		"128.8.126.5" // local satoshi: kale.cs.umd.edu
#define DEFAULT_PORT	28333

#define MAX_PENDING 5		// backlog size for listen()
#define MAX_PEERS	10		// maximum number of connected peers

typedef enum{
	CB_MESSAGE_HEADER_NETWORK_ID = 0,	// The network identidier bytes
	CB_MESSAGE_HEADER_TYPE = 4,			// The 12 character string for the message type
	CB_MESSAGE_HEADER_LENGTH = 16,		// The length of the message
	CB_MESSAGE_HEADER_CHECKSUM = 20,	// The checksum of the message
} CBMessageHeaderOffsets;

int peers_count = 0;

void help(){
	prt("commands: [cmd] [argument] ... \n");
	prt("    help : shows this message\n");
	prt("    quit : quits\n");
	prt("    version : sends version message client\n");
	prt("    ping : sends ping message to connected client\n");
	prt("\n");
}

int command(){
	// Read a line
	char *line = 0;
	size_t len = 0;
	getline(&line, &len, stdin);
	char cmd[64] = {0}; // this will crash if you enter bad strings in stdin!
	sscanf(line, " %s ", cmd);

	// Main interactive command dispatch
	if (!strcmp(cmd, "ping")) {
		prt("you said ping\n");
	} else if (!strcmp(cmd, "help")) {
		help();
	} else if (!strcmp(cmd, "version")) {
		prt("sending version\n");
	} else if (!strcmp(cmd, "quit") || !strcmp(cmd, "q")) {
		prt("quitting...\n");
		return 0; // party's over
	} else if (!strcmp(cmd, "")) {
	} else {
		prt("command not recognized: '%s'\n", cmd);
	}
	
	return 1; // rolling along
}

int listen_at(in_port_t port){
	int sock;
	if ((sock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0)
		sysfail("socket()");
	
	struct sockaddr_in addr;
	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = htonl(INADDR_ANY); // any incoming interface?
	addr.sin_port = htons(port);
	
	if (bind(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0)
		sysfail("bind()");
	if (listen(sock, MAX_PENDING) < 0)
		sysfail("listen()");
	
	prt("Listening at port %d\n", port);
	return sock;
}

int connect_first_peer(){
	int sd;
	if((sd = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0)
		sysfail("socket()");
	
	struct sockaddr_in addr;
	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_port = htons(DEFAULT_PORT);
	addr.sin_addr.s_addr = (((((25 << 8) | 126) << 8) | 8) << 8) | 128; // DEFAULT_IP

	if (connect(sd, (struct sockaddr *)&addr, sizeof addr) < 0)
		sysfail("connect()");

	prt("Connected to first peer at %s:%d\n", DEFAULT_IP, DEFAULT_PORT);
	return sd;
}

void release_peer(void *peer){
	// When the array is freed, free all peers in it and close their sockets
	CBPeer *p = peer;
	//deb("Closing socket %d\n", p->socketID);
	close(p->socketID);
	CBReleaseObject(p);
}

bool add_peer(CBAssociativeArray *peers, CBPeer *peer){
	if (NOT CBAssociativeArrayInsert(peers, peer, CBAssociativeArrayFind(peers, peer).position, NULL)){
		deb("Could not insert a peer into the peers array.\n");
		return false;
	}
	peers_count++;
	return true;
}

int main(int argc, char *argv[]){
	prt("CMSC417: Rudimentary bitcoin client.\n");
	prt("Andrew Badger, Thach Hoang. 2013.\n");
	help();
	
	// Create socket to detect incoming connections
	int serv_sock = listen_at(DEFAULT_PORT);
	
	// Connect to initial peer
	CBByteArray *ip = CBNewByteArrayWithDataCopy((uint8_t [16]){0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0xFF, 128, 8, 126, 25}, 16);
	CBNetworkAddress *peeraddr = CBNewNetworkAddress(0, ip, DEFAULT_PORT, CB_SERVICE_FULL_BLOCKS, false);
	CBPeer *init_peer = CBNewPeerByTakingNetworkAddress(peeraddr);
	init_peer->socketID = connect_first_peer();
	
	// Add initial peer to list of peers
	CBAssociativeArray peers;
	if (!CBInitAssociativeArray(&peers, CBKeyCompare, release_peer))
		fail("Could not create associative array for peers.\n");
	if (!add_peer(&peers, init_peer))
		fail("Could not insert first peer.\n");
	
	fd_set rfds;
	struct timeval tv;
	int retval;
	bool running = true;

	while (running) {
		// Watch stdin for user input
		FD_ZERO(&rfds);
		FD_SET(STDIN_FILENO, &rfds);
		
		// Watch all peers
		CBPosition it;
		if (CBAssociativeArrayGetFirst(&peers, &it)) {
			do {
				CBPeer *peer = it.node->elements[it.index];
				FD_SET(peer->socketID, &rfds);
			} while (!CBAssociativeArrayIterate(&peers, &it));
		}

		// Wait up to five seconds
		tv.tv_sec = 5;
		tv.tv_usec = 0;

		retval = select(1, &rfds, NULL, NULL, &tv);

		if (retval == -1) {
			perror("select()");
		} else if (retval) {
			if (FD_ISSET(STDIN_FILENO, &rfds))
				if (!command())
					running = false;
			
			// Handle peer connections...
		} else {
			// Nothing really matters...
		}
	}
	
	// Free all peer objects and close associated sockets
	CBFreeAssociativeArray(&peers);
	
	close(serv_sock);
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

void sysfail(const char *msg){
	perror(msg);
	exit(EXIT_FAILURE);
}

void prt(const char* fmt, ...){
	va_list args;
	va_start(args, fmt);
	vprintf(fmt, args);
	va_end(args);
}

void deb(const char* fmt, ...){
	if(!DEBUG)
		return;
	va_list args;
	va_start(args, fmt);
	vprintf(fmt, args);
	va_end(args);
}

