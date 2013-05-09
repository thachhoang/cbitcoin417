#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stdbool.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>

#include <netinet/in.h>
#include <sys/poll.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <string.h>

#include <CBAssociativeArray.h>
#include <CBByteArray.h>
#include <CBConstants.h>
#include <CBMessage.h>
#include <CBNetworkAddress.h>
#include <CBPeer.h>
#include <CBVersion.h>

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

static void print_hex(CBByteArray *str) {
	int i = 0;
	uint8_t *ptr = str->sharedData->data;
	for (; i < str->length; i++) deb("%02x", ptr[str->offset + i]);
	deb("\n");
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
		prt("sending version (not implemented)\n");
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
	int sd, opt;
	struct sockaddr_in addr;
	if ((sd = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0)
		sysfail("socket() failed");
	
	if ((setsockopt(sd, SOL_SOCKET, SO_REUSEADDR, (char *)&opt, sizeof(opt)) < 0)) {
		close(sd);
		sysfail("setsockopt() failed");
	}
	if ((fcntl(sd, F_SETFL, O_NONBLOCK) < 0)) {
		close(sd);
		sysfail("fcntl() failed");
	}
	
	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = htonl(INADDR_ANY);
	addr.sin_port = htons(port);
	
	if (bind(sd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
		close(sd);
		sysfail("bind() failed");
	}
	if (listen(sd, MAX_PENDING) < 0) {
		close(sd);
		sysfail("listen() failed");
	}
	
	prt("Listening at port %d\n", port);
	return sd;
}

int connect_first_peer(){
	int sd;
	if((sd = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0)
		sysfail("socket()");
	
	if ((fcntl(sd, F_SETFL, O_NONBLOCK) < 0)) {
		close(sd);
		sysfail("fcntl() failed");
	}
	
	struct sockaddr_in addr;
	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_port = htons(DEFAULT_PORT);
	addr.sin_addr.s_addr = (((((25 << 8) | 126) << 8) | 8) << 8) | 128; // DEFAULT_IP

	connect(sd, (struct sockaddr *)&addr, sizeof addr);
	
	fd_set wfds;
	struct timeval tv;
	
	FD_ZERO(&wfds);
	FD_SET(sd, &wfds);
	tv.tv_sec = 5;
	tv.tv_usec = 0;
	
	int rv = select(sd + 1, NULL, &wfds, NULL, &tv);
	if (rv <= 0) {
		if (rv < 0)
			perror("select()");
		prt("Failed to reach first peer at %s:%d.\n", DEFAULT_IP, DEFAULT_PORT);
		return -1;
	} else
		prt("Connected to first peer at %s:%d.\n", DEFAULT_IP, DEFAULT_PORT);
	
	return sd;
}

bool add_peer(CBAssociativeArray *peers, CBPeer *peer){
	if (NOT CBAssociativeArrayInsert(peers, peer, CBAssociativeArrayFind(peers, peer).position, NULL)){
		deb("Could not insert a peer into the peers array.\n");
		return false;
	}
	peers_count++;
	return true;
}

void send_version(CBPeer *peer){
	//deb("Prepare version msg for peer at sock %d\n", peer->socketID);
	int sd = peer->socketID;
	
    CBByteArray *ip = CBNewByteArrayWithDataCopy((uint8_t [16]){0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0xFF, 127, 0, 0, 1}, 16);
    CBByteArray *ua = CBNewByteArrayFromString("cmsc417versiona", '\00');
    CBNetworkAddress * sourceAddr = CBNewNetworkAddress(0, ip, 0, CB_SERVICE_FULL_BLOCKS, false);
    int32_t vers = 70001;
    int nonce = rand();
    CBVersion * version = CBNewVersion(vers, CB_SERVICE_FULL_BLOCKS, time(NULL), &peer->base, sourceAddr, nonce, ua, 0);
    CBMessage *message = CBGetMessage(version);
    char header[24];
    memcpy(header + CB_MESSAGE_HEADER_TYPE, "version\0\0\0\0\0", 12);

    /* Compute length, serialized, and checksum */
    uint32_t len = CBVersionCalculateLength(version);
    message->bytes = CBNewByteArrayOfSize(len);
    len = CBVersionSerialise(version, false);
    if (message->bytes) {
        // Make checksum
        uint8_t hash[32];
        uint8_t hash2[32];
        CBSha256(CBByteArrayGetData(message->bytes), message->bytes->length, hash);
        CBSha256(hash, 32, hash2);
        message->checksum[0] = hash2[0];
        message->checksum[1] = hash2[1];
        message->checksum[2] = hash2[2];
        message->checksum[3] = hash2[3];
    }
    CBInt32ToArray(header, CB_MESSAGE_HEADER_NETWORK_ID, NETMAGIC);
    CBInt32ToArray(header, CB_MESSAGE_HEADER_LENGTH, message->bytes->length);
    // Checksum
    memcpy(header + CB_MESSAGE_HEADER_CHECKSUM, message->checksum, 4);

    // Send the header
    int rv = send(sd, header, 24, 0);
    if (rv < 0) {
    	perror("send()");
    	return;
    }
    
    // Send the message
    deb("message len: %d\n", message->bytes->length);
    deb("checksum: %x\n", *((uint32_t *) message->checksum));
    print_hex(message->bytes);
	rv = send(sd, message->bytes->sharedData->data+message->bytes->offset, message->bytes->length, 0);
    if (rv < 0) {
    	perror("send()");
    	return;
    }
    
	peer->versionSent = true;
}

bool read_message(int sd, CBPeer *peer){
	// return false to close current socket and remove peer
	
	if (!peer)
		return false; // should not happen
	
	// Read the header
	char header[24];
	socklen_t nread = 0;
	nread = recv(sd, header, 24, 0);
	if (nread < 0) {
		if (errno != EWOULDBLOCK) {
			// Unexpected error
			perror("recv() failed");
			return false;
		}
	} else if (nread == 0) {
		deb("empty header\n");
		return true;
	}
	
	deb("<==\nreceived header\n");
	if (*((uint32_t *)(header + CB_MESSAGE_HEADER_NETWORK_ID)) != NETMAGIC) {
		printf("wrong netmagic\n");
		return true;
	}
	
	// Read the payload
	unsigned int length = *((uint32_t *)(header + CB_MESSAGE_HEADER_LENGTH));
	char *payload = (char *) malloc(length);
	nread = 0;
	if (length) nread = recv(sd, payload, length, 0);
	if (nread != length) {
		deb("incomplete read %u %u \n", nread, length);
	} else {
		deb("read payload of %u bytes\n", nread);
	}
	
	if (!strncmp(header+CB_MESSAGE_HEADER_TYPE, "version\0\0\0\0\0", 12)) {
		prt("received version header\n");
	}
	if (!strncmp(header+CB_MESSAGE_HEADER_TYPE, "verack\0\0\0\0\0\0", 12)) {
		prt("received verack header\n");
	}
	if (!strncmp(header+CB_MESSAGE_HEADER_TYPE, "ping\0\0\0\0\0\0\0\0", 12)) {
		prt("received ping header\n");
	}
	if (!strncmp(header+CB_MESSAGE_HEADER_TYPE, "pong\0\0\0\0\0\0\0\0", 12)) {
		prt("received pong header\n");
	}
	if (!strncmp(header+CB_MESSAGE_HEADER_TYPE, "inv\0\0\0\0\0\0\0\0\0", 12)) {
		prt("received inv header\n");
	}
	if (!strncmp(header+CB_MESSAGE_HEADER_TYPE, "addr\0\0\0\0\0\0\0\0", 12)) {
		prt("received addr header\n");
	}
	
	deb("==>\n");
	return true;
}

int main(int argc, char *argv[]){
	prt("CMSC417: Rudimentary bitcoin client.\n");
	prt("Andrew Badger, Thach Hoang. 2013.\n");
	help();
	
	// Create socket to detect incoming connections
	int listen_sd = listen_at(DEFAULT_PORT);
	
	// Create list of peers
	CBAssociativeArray peers;
	if (!CBInitAssociativeArray(&peers, CBKeyCompare, CBReleaseObject))
		fail("Could not create associative array for peers.\n");
	
	// Connect to initial peer
	CBPeer *init_peer = NULL;
	int first_peer_sd = connect_first_peer();
	if (first_peer_sd > 0) {
		CBByteArray *ip = CBNewByteArrayWithDataCopy((uint8_t [16]){0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0xFF, 128, 8, 126, 25}, 16);
		CBNetworkAddress *peeraddr = CBNewNetworkAddress(0, ip, DEFAULT_PORT, CB_SERVICE_FULL_BLOCKS, false);
		init_peer = CBNewPeerByTakingNetworkAddress(peeraddr);
		init_peer->socketID = first_peer_sd;
		init_peer->versionSent = false;
		init_peer->getAddresses = false;
		send_version(init_peer);
		
		// Add initial peer to list of peers
		if (!add_peer(&peers, init_peer))
			prt("Could not insert first peer.\n");
	}
	
	struct pollfd fds[200];
	int nfds = 0, current_size;
	int new_sd = 0;
	int rv;
	int timeout = 60 * 1000; // 1 minute
	int i, j;
	bool running = true, compress_array = false;
	CBPosition it;
	CBPeer *peer = NULL;

	memset(fds, 0 , sizeof(fds));
	
	// Watch initial listening socket
	fds[0].fd = listen_sd;
	fds[0].events = POLLIN;
	nfds++;

	// Watch keyboard input
	fds[1].fd = STDIN_FILENO;
	fds[1].events = POLLIN;
	nfds++;

	// Watch initial peers
	if (CBAssociativeArrayGetFirst(&peers, &it)) {
		do {
			peer = it.node->elements[it.index];
			fds[nfds].fd = peer->socketID;
			fds[nfds].events = POLLIN;
			nfds++;
		} while (!CBAssociativeArrayIterate(&peers, &it));
	}
	
	while (running) {
		// Outgoing messages
		peer = NULL;
		/*
		if (CBAssociativeArrayGetFirst(&peers, &it)) {
			do {
				peer = it.node->elements[it.index];
			} while (!CBAssociativeArrayIterate(&peers, &it));
		}
		*/
		
		rv = poll(fds, nfds, timeout);
		if (rv < 0) {
			perror("poll()");
			break;
		}
		if (rv == 0) {
			continue; // timeout
		}

		// Readable sockets exist. Find them.
		current_size = nfds;
		for (i = 0; i < current_size; i++) {
			// Nothing happens
			if(fds[i].revents == 0)
				continue;

			// We will not deal with unexpected events
			if(fds[i].revents != POLLIN) {
				printf("Error: revents = %d\n", fds[i].revents);
				running = false;
				break;
			}
			
			if (fds[i].fd == STDIN_FILENO) {
				// User input
				if (!command())
					running = false;
			} else if (fds[i].fd == listen_sd) {
				// Listening socket is readable
				// Accept incoming connections: possible new peers
				do {
					// If accept fails with EWOULDBLOCK, then all incoming connections
					// have been accepted. Other failures will end the program.
					
					// TODO: when accepting connections, create a new peer object,
					// assign to it proper network addr and socket, finally add socket
					// to the watch list of poll(). Uncomment and finish the following block.
					
					/*
					new_sd = accept(listen_sd, NULL, NULL);
					if (new_sd < 0) {
						if (errno != EWOULDBLOCK) {
							perror("accept() failed");
							running = false;
						}
						break;
					}
					
					fds[nfds].fd = new_sd;
					fds[nfds].events = POLLIN;
					nfds++;
					
					deb("New incoming connection: %d\n", new_sd);
					*/
					
					deb("New incoming connection: not handled\n");
				} while (new_sd != -1);
			} else {
				// Not listening socket. Check other connections.
				//deb("Descriptor %d is readable.\n", fds[i].fd);
				peer = NULL;
				if (CBAssociativeArrayGetFirst(&peers, &it)) {
					do {
						peer = it.node->elements[it.index];
						if (peer->socketID == fds[i].fd) {
							//deb("Desc %d is a peer.\n", peer->socketID);
							break;
						}
					} while (!CBAssociativeArrayIterate(&peers, &it));
				}
				
				bool success = read_message(fds[i].fd, peer);
				if (!success) {
					close(fds[i].fd);
					fds[i].fd = -1;
					compress_array = true;
					CBAssociativeArrayDelete(&peers, CBAssociativeArrayFind(&peers, peer).position, true);
				}
			}
		} // descriptor loop

		// Some connections were closed. Remove their descriptors.
		// Squeeze together the array (moving .fd fields).
		// The other fields are always the same (events = POLLIN), so we let them be.
		if (compress_array) {
			compress_array = false;
			for (i = 0; i < nfds; i++) {
				if (fds[i].fd == -1) {
					for(j = i; j < nfds; j++) {
						fds[j].fd = fds[j+1].fd;
					}
					nfds--;
				}
			}
		}

	} // infinity
	
	// Free all peer objects and close associated sockets
	CBFreeAssociativeArray(&peers);
	for (i = 0; i < nfds; i++)
		if (fds[i].fd >= 0)
			close(fds[i].fd);

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

