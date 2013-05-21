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
#include <signal.h>
#include <string.h>

#include <CBAddressBroadcast.h>
#include <CBAssociativeArray.h>
#include <CBBlock.h>
#include <CBByteArray.h>
#include <CBChainDescriptor.h>
#include <CBConstants.h>
#include <CBFullValidator.h>
#include <CBInventoryBroadcast.h>
#include <CBGetBlocks.h>
#include <CBMessage.h>
#include <CBNetworkAddress.h>
#include <CBPeer.h>
#include <CBVersion.h>

#define DEBUG 1

void fail(const char *, ...); // exit in failure with custom message
void sysfail(const char *);   // perror wrapper
void prt(const char *, ...);  // printf wrapper
void deb(const char *, ...);  // printf only in debug mode

//#define NETMAGIC 0xffffffff // mainnet
//#define NETMAGIC 0x0709110B // testnet
#define NETMAGIC 0xd0b4bef9 // umdnet
#define VERS 70001

//#define DEFAULT_IP      (uint8_t [16]) {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0xFF, 127, 0, 0, 1}
#define DEFAULT_IP      (uint8_t [16]) {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0xFF, 128, 8, 126, 25} // local satoshi: kale.cs.umd.edu
#define DEFAULT_PORT    28333
#define SELF_IP         (uint8_t [16]) {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0xFF, 127, 0, 0, 1}
#define SELF_PORT       28333

#define MAX_INV       500  // max number of hashes in inv
#define MAX_PENDING    20  // backlog size for listen()
#define PING_INTERVAL  60  // ping peers every 60 seconds

typedef enum {
	CB_MESSAGE_HEADER_NETWORK_ID = 0,	// The network identidier bytes
	CB_MESSAGE_HEADER_TYPE = 4,			// The 12 character string for the message type
	CB_MESSAGE_HEADER_LENGTH = 16,		// The length of the message
	CB_MESSAGE_HEADER_CHECKSUM = 20,	// The checksum of the message
} CBMessageHeaderOffsets;

typedef enum {
	DEFAULT, PING, GETADDR, GETBLOCKS, STAT, QUIT, VERSION
} commands;

// Block storage
CBFullValidator *validator;

// List of peers
CBAssociativeArray *peers;

void help(){
	prt("commands: [cmd] [argument] ... \n");
	prt("    help : shows this message\n");
	prt("    quit : quits\n");
	prt("    version : sends version message to initial peer\n");
	prt("    stat : returns the number of connected peers\n");
	prt("    ping : sends ping message to initial peer\n");
	prt("\n");
}

static void prt_hex(uint8_t *ptr, int len) {
	int i = 0; for (; i < len; i++) prt("%02x", ptr[i]); prt("\n");
}
/*
static void prt_hex_ba(CBByteArray *str) {
	prt_hex(str->sharedData->data + str->offset, str->length);
}
*/
static void deb_hex(uint8_t *ptr, int len) {
	int i = 0; for (; i < len; i++) deb("%02x", ptr[i]);
}

static void deb_hexn(uint8_t *ptr, int len) {
	deb_hex(ptr, len); deb("\n");
}

static void deb_hex_ba(CBByteArray *str) {
	deb_hexn(str->sharedData->data + str->offset, str->length);
}

static void str_ip(char *buffer, uint8_t *ip, int offset) {
	sprintf(buffer, "%d.%d.%d.%d", ip[offset], ip[offset+1], ip[offset+2], ip[offset+3]);
}

static void prt_ip(CBByteArray *str) {
	char *buffer = malloc(str->length * sizeof(char));
	uint8_t *ptr = str->sharedData->data + str->offset;
	str_ip(buffer, ptr, 12);
	prt("%s", buffer);
	free(buffer);
}

int command(){
	int rv = DEFAULT;
	// Read a line
	char *line = 0;
	size_t len = 0;
	getline(&line, &len, stdin);
	char cmd[64] = {0}; // this will crash if you enter bad strings in stdin!
	sscanf(line, " %s ", cmd);

	// Main interactive command dispatch
	if (!strcmp(cmd, "help")) {
		help();
	} else if (!strcmp(cmd, "addr")) {
		rv = GETADDR;
	} else if (!strcmp(cmd, "blocks")) {
		rv = GETBLOCKS;
	} else if (!strcmp(cmd, "ping")) {
		rv = PING;
	} else if (!strcmp(cmd, "stat")) {
		rv = STAT;
	} else if (!strcmp(cmd, "version")) {
		rv = VERSION;
	} else if (!strcmp(cmd, "quit") || !strcmp(cmd, "q")) {
		rv = QUIT; // party's over
	} else if (!strcmp(cmd, "")) {
	} else {
		prt("Command not recognized: '%s'\n", cmd);
	}
	
	free(line);
	return rv; // rolling along
}

int listen_at(in_port_t port){
	int sd, opt = 0;
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

	prt("Listening at port %d.\n", port);
	return sd;
}

int connect_peer(uint8_t* arr, in_port_t port){
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
	addr.sin_port = htons(port);
	addr.sin_addr.s_addr = (((((arr[15] << 8) | arr[14]) << 8) | arr[13]) << 8) | arr[12];

	connect(sd, (struct sockaddr *)&addr, sizeof addr);

	fd_set wfds;
	struct timeval tv;

	FD_ZERO(&wfds);
	FD_SET(sd, &wfds);
	tv.tv_sec = 5;
	tv.tv_usec = 0;

	char *addr_str = calloc(200, sizeof(char));
	str_ip(addr_str, arr, 12);
	int rv = select(sd + 1, NULL, &wfds, NULL, &tv);
	if (rv <= 0) {
		if (rv < 0)
			perror("select()");
		prt("Failed to reach first peer at %s:%d.\n", addr_str, port);
		return -1;
	} else
		prt("Connected to first peer at %s:%d.\n", addr_str, port);

	free(addr_str);
	return sd;
}

bool add_peer(CBPeer *peer){
	if (!peer)
		return false;
	if (NOT CBAssociativeArrayInsert(peers, peer, CBAssociativeArrayFind(peers, peer).position, NULL)){
		deb("Could not insert a peer into the peers array.\n");
		return false;
	}
	return true;
}

void free_peer(void *p){
	CBPeer *peer = (CBPeer *)p;
	if (peer->versionMessage)
		CBFreeVersion(peer->versionMessage);
	CBReleaseObject(peer);
}

ssize_t send_buffer(int sd, uint8_t *buffer, uint32_t length){
	if (length == 0)
		return 0;

	uint32_t len = length;
	ssize_t nsent = 0;
	bool sending = true;
	uint8_t *ptr = buffer;

	while (sending) {
		nsent = send(sd, ptr, len, 0);
		if (nsent < 0) {
			if (errno == EWOULDBLOCK || errno == EAGAIN)
				continue;
			else
				return nsent;
		}
		deb("send: %d/%d\n", nsent, len);
		if (nsent == 0) return 0;
		if (nsent < len) {
			ptr += nsent;
			len -= nsent;
		} else if (nsent == len) {
			sending = false;
		}
	}

	return length;
}

ssize_t send_message(int sd, uint8_t *header, uint8_t *payload, ssize_t length){
	// Return -1 on error, 0 on closed connection, message length on success

	ssize_t h_len = send_buffer(sd, header, 24);
	if (h_len != 24) {
		deb("send header failed: %d/24\n", h_len);
		return (h_len <= 0) ? h_len : -1;
	}
	deb("sent header\n");

	ssize_t p_len = length - 24;
	if (p_len == 0 || !payload) return h_len; // verack and others without payload

	ssize_t len = send_buffer(sd, payload, p_len);
	if (len != p_len) {
		deb("send payload failed: %d/%d\n", len, p_len);
		return (len <= 0) ? len : -1;
	}
	deb("sent payload: %d bytes\n", p_len);

	return h_len + p_len;
}

void make_header(uint8_t **header, CBMessage *message, char *header_type){
	uint8_t hash[32];
	uint8_t hash2[32];
	CBSha256(CBByteArrayGetData(message->bytes), message->bytes->length, hash);
	CBSha256(hash, 32, hash2);

	message->checksum[0] = hash2[0];
	message->checksum[1] = hash2[1];
	message->checksum[2] = hash2[2];
	message->checksum[3] = hash2[3];

	*header = malloc(24);
	uint8_t *tmp = *header;
	uint32_t magic = NETMAGIC;

	memcpy(tmp + CB_MESSAGE_HEADER_CHECKSUM, message->checksum, 4);
	memcpy(tmp + CB_MESSAGE_HEADER_TYPE, header_type, 12);
	CBInt32ToArray(tmp, CB_MESSAGE_HEADER_NETWORK_ID, magic);
	CBInt32ToArray(tmp, CB_MESSAGE_HEADER_LENGTH, message->bytes->length);

	//deb_hexn(tmp, 24);
}

void send_pingpong(CBPeer *peer, uint64_t nonce, bool ping){
	prt(">> Sending %s: ", ping ? "ping" : "pong");
	prt_ip(peer->versionMessage->addSource->ip);

	int sd = peer->socketID;

	prt(", nonce: "); prt_hex((uint8_t *) &nonce, 8); prt("\n");
	CBByteArray *bytes = CBNewByteArrayOfSize(8);
	CBByteArraySetInt64(bytes, 0, nonce);

	CBMessage *message = CBNewMessageByObject();
	message->bytes = bytes;

	uint8_t *header;
	make_header(&header, message, ping ? "ping\0\0\0\0\0\0\0\0" : "pong\0\0\0\0\0\0\0\0");

	int rv = send_message(sd, header, message->bytes->sharedData->data, message->bytes->length + 24);
	if (rv == 32) {
		deb("send succeeds\n");
	}

	free(header);
	CBFreeMessage(message);
}

void send_ping(CBPeer *peer){
	uint64_t ui64 = ((uint64_t) rand() << 32) | rand();
	send_pingpong(peer, ui64, true);
}

void send_pong(CBPeer *peer, uint64_t nonce){
	send_pingpong(peer, nonce, false);
}

void send_getaddr(CBPeer *peer){
	prt(">> Sending getaddr: ");
	prt_ip(peer->versionMessage->addSource->ip); prt("\n");
	int sd = peer->socketID;

	CBByteArray *empty = CBNewByteArrayFromString("", false);
	CBMessage *message = CBNewMessageByObject();
	message->bytes = empty;

	uint8_t *header;
	make_header(&header, message, "getaddr\0\0\0\0\0");
	int rv = send_message(sd, header, NULL, 24);
	if (rv == 24) {
		deb("send succeeds\n");
	}

	free(header);
	CBFreeMessage(message);
}

void send_verack(CBPeer *peer){
	if (!peer->versionSent)
		return;

	prt(">> Sending verack: ");
	prt_ip(peer->versionMessage->addSource->ip);
	prt("\n");
	int sd = peer->socketID;

	CBByteArray *empty = CBNewByteArrayFromString("", false);
	CBMessage *message = CBNewMessageByObject();
	message->bytes = empty;

	uint8_t *header;
	make_header(&header, message, "verack\0\0\0\0\0\0");

	int rv = send_message(sd, header, NULL, 24);
	if (rv == 24) {
		deb("send succeeds\n");
		peer->versionAck = true;
	}

	free(header);
	CBFreeMessage(message);
}

void send_version(CBPeer *peer){
	deb(">> Sending version: socket %d\n", peer->socketID);
	int sd = peer->socketID;

	CBByteArray *ip = CBNewByteArrayWithDataCopy(SELF_IP, 16);
	CBByteArray *ua = CBNewByteArrayFromString("cmsc417versiona", '\00');
	CBNetworkAddress *sourceAddr = CBNewNetworkAddress(0, ip, SELF_PORT, CB_SERVICE_FULL_BLOCKS, false);
	int32_t vers = VERS;
	int nonce = rand();
	CBVersion *version = CBNewVersion(vers, CB_SERVICE_FULL_BLOCKS, time(NULL), &peer->base, sourceAddr, nonce, ua, 0);
	CBMessage *message = CBGetMessage(version);

	/* Compute length, serialized, and checksum */
	uint32_t len = CBVersionCalculateLength(version);
	message->bytes = CBNewByteArrayOfSize(len);
	len = CBVersionSerialise(version, false);

	uint8_t *header;
	if (message->bytes) {
		make_header(&header, message, "version\0\0\0\0\0");
		deb("Message length: %d\n", message->bytes->length);
		deb("Checksum: %x\n", *((uint32_t *) message->checksum));
		deb_hex_ba(message->bytes);

		int rv = send_message(sd, header, message->bytes->sharedData->data+message->bytes->offset, message->bytes->length + 24);
		if (rv == message->bytes->length + 24) {
			deb("send succeeds\n");
			peer->versionSent = true;
		}
	}

	free(header);
	CBFreeVersion(version);
	CBFreeNetworkAddress(sourceAddr);
	CBFreeByteArray(ip);
	CBFreeByteArray(ua);
}

void send_getblocks(CBPeer *peer){
	prt(">> Sending getblocks: ");
	prt_ip(peer->versionMessage->addSource->ip);
	prt("\n");
	int sd = peer->socketID;

	CBBlock *last_block = CBBlockChainStorageLoadBlock(validator, validator->branches[validator->mainBranch].lastValidation, validator->mainBranch);
	uint8_t *rawhash = CBBlockGetHash(last_block);
	CBChainDescriptor *chain = CBNewChainDescriptor();
	CBByteArray *stophash = CBNewByteArrayWithDataCopy(rawhash, 32);
	if (!CBChainDescriptorAddHash(chain, stophash))
		fail("Failed to add hash to chain descriptor\n");

	int32_t vers = VERS;
	CBGetBlocks *getblocks = CBNewGetBlocks(vers, chain, stophash);
	CBMessage *message = CBGetMessage(getblocks);

	uint32_t len = CBGetBlocksCalculateLength(getblocks);
	message->bytes = CBNewByteArrayOfSize(len);
	len = CBGetBlocksSerialise(getblocks, false);
	uint8_t *header;
	if (message->bytes) {
		make_header(&header, message, "getblocks\0\0\0");
		deb("message len: %d\n", message->bytes->length);
		deb("checksum: %x\n", *((uint32_t *) message->checksum));
		deb_hex_ba(message->bytes);

		int rv = send_message(sd, (uint8_t *)header, message->bytes->sharedData->data+message->bytes->offset, message->bytes->length + 24);
		if (rv == message->bytes->length + 24) {
			deb("send succeeds\n");
		}
	}

	free(header);
	CBFreeBlock(last_block);
	CBReleaseObject(chain);
	CBReleaseObject(stophash);
	CBFreeGetBlocks(getblocks);
}

void send_getdata(CBPeer *peer, CBInventoryBroadcast *inv){
	prt(">> Sending getdata: "); prt_ip(peer->versionMessage->addSource->ip); prt("\n");
	int sd = peer->socketID;

	deb("inv count: %d\n", inv->itemNum);
	CBInventoryBroadcast *getdata = CBNewInventoryBroadcast();
	getdata->items = malloc(inv->itemNum * sizeof(CBInventoryItem));
	if (getdata->items == NULL)
		sysfail("malloc() failed");

	// Check if blocks exist in database, if not, add block hash to getdata
	uint16_t i, k = 0, inv_count = inv->itemNum;// > 10 ? 10 : inv->itemNum;
	uint8_t *hash;
	CBInventoryItem *item;
	for (i = 0; i < inv_count; i++) {
		deb("Item %4d ", i);
		item = inv->items[i];
		if (item->type == CB_INVENTORY_ITEM_BLOCK) {
			deb("[block ");
			hash = item->hash->sharedData->data + item->hash->offset;
			deb_hex(hash, 4); deb("]: ");
			if (!CBBlockChainStorageBlockExists(validator, hash)) {
				deb("DNE: add to getdata payload");
				getdata->items[k++] = CBNewInventoryItem(item->type, item->hash);
			}
		} else if (item->type == CB_INVENTORY_ITEM_TRANSACTION) {
			deb("[tx]");
		} else if (item->type == CB_INVENTORY_ITEM_ERROR) {
			deb("[err]");
		}
		deb("\n");
	}

	CBFreeInventoryBroadcast(inv);

	getdata->itemNum = k;
	getdata->items = realloc(getdata->items, getdata->itemNum * sizeof(CBInventoryItem));
	if (getdata->items == NULL)
		sysfail("realloc() failed");

	CBMessage *message = CBGetMessage(getdata);
	message->bytes = CBNewByteArrayOfSize(CBInventoryBroadcastCalculateLength(getdata));
	CBInventoryBroadcastSerialise(getdata, false);

	uint8_t *header;
	if (message->bytes) {
		make_header(&header, message, "getdata\0\0\0\0\0");
		deb("Message length: %d\n", message->bytes->length);
		int rv = send_message(sd, header, message->bytes->sharedData->data+message->bytes->offset, message->bytes->length + 24);
		if (rv == message->bytes->length + 24) {
			deb("send succeeds\n");
		}
	}

	free(header);
	CBFreeInventoryBroadcast(getdata);
}

void send_inv(CBPeer *peer, CBGetBlocks *gb){
	prt(">> Sending inv to: "); prt_ip(peer->versionMessage->addSource->ip); prt("\n");
	int sd = peer->socketID;

	CBByteArray *stop_hash_ba = gb->stopAtHash;
	CBByteArray *start_hash_ba = gb->chainDescriptor->hashes[0];
	uint8_t *stop_hash = stop_hash_ba->sharedData->data + stop_hash_ba->offset;
	uint8_t *start_hash = start_hash_ba->sharedData->data + start_hash_ba->offset;
	uint8_t branch;
	uint32_t start_index, stop_index, inv_count;
	uint32_t last_index = validator->branches[validator->mainBranch].lastValidation;

	// Start index
	if (!CBBlockChainStorageGetBlockLocation(validator, start_hash, &branch, &start_index)) {
		// We don't have the start block.
		return;
	}
	if (branch != validator->mainBranch) {
		// We're off the main branch. Just start from genesis.
		start_index = 0;
	}

	// Stop index
	if (!CBBlockChainStorageGetBlockLocation(validator, stop_hash, &branch, &stop_index) || stop_index <= start_index) {
		// We don't have the stop block
		stop_index = start_index + MAX_INV;
	}
	if (branch != validator->mainBranch) {
		// We're off the main branch. Just stop 500 blocks after the start block.
		stop_index = start_index + MAX_INV;
	}
	if (stop_index > last_index) {
		// We only have blocks up to the last validated block on the main chain.
		stop_index = last_index;
	}

	inv_count = stop_index - start_index;
	deb("%d blocks from %d to %d\n", inv_count, start_index + 1, stop_index);

	CBInventoryBroadcast *inv = CBNewInventoryBroadcast();
	inv->items = malloc(inv_count * sizeof(CBInventoryItem));
	if (inv->items == NULL)
		sysfail("malloc() failed");

	// Load hashes, build the inventory
	uint16_t i, k = 0;
	CBBlock *block;
	CBByteArray *hash;
	for (i = start_index + 1; i <= stop_index; i++) {
		block = CBBlockChainStorageLoadBlock(validator, i, validator->mainBranch);
		if (!block)
			continue;
		hash = CBNewByteArrayWithDataCopy(CBBlockGetHash(block), 32);
		inv->items[k++] = CBNewInventoryItem(CB_INVENTORY_ITEM_BLOCK, hash);
		CBReleaseObject(hash);
		CBFreeBlock(block);
	}

	inv->itemNum = k;
	if (k != inv_count) {
		inv->items = realloc(inv->items, inv->itemNum * sizeof(CBInventoryItem));
		if (inv->items == NULL)
			sysfail("realloc() failed");
	}

	CBMessage *message = CBGetMessage(inv);
	message->bytes = CBNewByteArrayOfSize(CBInventoryBroadcastCalculateLength(inv));
	CBInventoryBroadcastSerialise(inv, false);

	uint8_t *header;
	if (message->bytes) {
		make_header(&header, message, "inv\0\0\0\0\0\0\0\0\0");
		deb("Message length: %d\n", message->bytes->length);
		int rv = send_message(sd, header, message->bytes->sharedData->data+message->bytes->offset, message->bytes->length + 24);
		if (rv == message->bytes->length + 24) {
			deb("send succeeds\n");
		}
	}

	free(header);
	CBFreeInventoryBroadcast(inv);
	CBFreeGetBlocks(gb);
}

void send_block(CBPeer *peer, CBInventoryBroadcast *gd){
	prt(">> Sending blocks to: "); prt_ip(peer->versionMessage->addSource->ip); prt("\n");
	int sd = peer->socketID;

	deb("getdata count: %d\n", gd->itemNum);
	uint16_t i, gd_count = gd->itemNum;
	uint8_t *hash;
	uint8_t branch;
	uint32_t index;
	CBInventoryItem *item;
	CBBlock *block;
	CBMessage *message;
	for (i = 0; i < gd_count; i++) {
		deb("Item %4d ", i);
		item = gd->items[i];
		if (item->type == CB_INVENTORY_ITEM_BLOCK) {
			hash = item->hash->sharedData->data + item->hash->offset;
			deb("[block "); deb_hex(hash, 4); deb("]\n");
			if (CBBlockChainStorageGetBlockLocation(validator, hash, &branch, &index)) {
				block = CBBlockChainStorageLoadBlock(validator, index, branch);
				message = CBGetMessage(block);

				uint8_t *header;
				if (message->bytes) {
					make_header(&header, message, "block\0\0\0\0\0\0\0");
					deb("Message length: %d\n", message->bytes->length);
					int rv = send_message(sd, header, message->bytes->sharedData->data+message->bytes->offset, message->bytes->length + 24);
					if (rv == message->bytes->length + 24) {
						deb("send succeeds\n");
					}
				}

				free(header);
				CBFreeBlock(block);
			}
		} else if (item->type == CB_INVENTORY_ITEM_TRANSACTION) {
			deb("[tx]\n");
		} else if (item->type == CB_INVENTORY_ITEM_ERROR) {
			deb("[err]\n");
		}
	}

	CBFreeInventoryBroadcast(gd);
}

ssize_t recv_buffer(int sd, uint8_t **buffer, uint32_t length){
	if (length == 0)
		return 0;

	uint32_t len = length;
	ssize_t nread = 0;
	bool reading = true;

	*buffer = malloc(length);
	uint8_t *ptr = *buffer;

	while (reading) {
		nread = recv(sd, ptr, len, 0);
		if (nread < 0) {
			if (errno == EWOULDBLOCK || errno == EAGAIN)
				continue;
			else
				return nread;
		}
		if (nread == 0) return 0;
		deb("recv: %d/%d\n", nread, len);
		if (nread < len) {
			ptr += nread;
			len -= nread;
		} else if (nread == len) {
			reading = false;
		}
	}

	return length;
}

ssize_t recv_message(int sd, uint8_t **header, uint8_t **payload){
	// Return -1 on error, 0 on closed connection, message length on success

	ssize_t h_len = recv_buffer(sd, header, 24);
	if (h_len != 24) {
		free(*header);
		return (h_len <= 0) ? h_len : -1;
	}
	deb("received header\n");

	ssize_t p_len = *((uint32_t *)(*header + CB_MESSAGE_HEADER_LENGTH));
	if (p_len == 0) return h_len; // verack and others without payload

	ssize_t len = recv_buffer(sd, payload, p_len);
	if (len != p_len) {
		free(*header);
		free(*payload);
		return (len <= 0) ? len : -1;
	}
	deb("received payload: %d bytes\n", p_len);

	if (*((uint32_t *)(*header + CB_MESSAGE_HEADER_NETWORK_ID)) != NETMAGIC) {
		deb("wrong netmagic\n");
		free(*header);
		free(*payload);
		return -1;
	}

	return h_len + p_len;
}

bool parse_message(int sd, CBPeer *peer){
	// Return false to close current socket and remove peer
	bool new_peer = !peer;

	char end[] = "==>\n\n";
	deb("<== ");
	deb(new_peer ? "new peer at %d\n" : "old peer at %d\n", sd);

	uint8_t *header_p;
	uint8_t *payload;
	ssize_t length = recv_message(sd, &header_p, &payload);

	if (length <= 0)
		deb("length: %d\n%s", length, end);
	if (length == -1)
		return !new_peer; // if new peer, close socket
	if (length == 0)
		return false; // closed connection

	if (new_peer || !peer->versionMessage)
		prt("Incoming message: %u bytes\n", length);
	else {
		prt("Incoming message from ");
		prt_ip(peer->versionMessage->addSource->ip);
		prt(": %u bytes\n", length);
	}

	char *header = (char *) header_p;
	deb("received %s header\n", header+CB_MESSAGE_HEADER_TYPE);
	
	CBByteArray *bytes;
	if (length > 24)
		bytes = CBNewByteArrayWithDataCopy(payload, length - 24);
	
	// version
	
	if (!strncmp(header+CB_MESSAGE_HEADER_TYPE, "version\0\0\0\0\0", 12)) {
		CBVersion *version = CBNewVersionFromData(bytes);
		CBVersionDeserialise(version);
		prt_ip(version->addRecv->ip); prt("\n");
		if (new_peer) {
			// Parse network address and make this connection a peer
			prt("Correct version message received. New peer at ");
			prt_ip(version->addSource->ip);
			prt(":%d.\n", version->addSource->port);

			CBNetworkAddress *addr = version->addSource;
			peer = CBNewPeerByTakingNetworkAddress(CBNewNetworkAddress(addr->lastSeen, addr->ip, addr->port, addr->services, addr->isPublic));
			peer->socketID = sd;
			peer->connectionWorking = true;

			// A new peer is created following a version exchange.
			if (!add_peer(peer))
				prt("Could not insert peer.\n");
		}
		if (peer) {
			peer->versionMessage = version;
			if (!peer->versionSent)
				send_version(peer);
			send_verack(peer);
		}
	} else if (new_peer) {
		deb("No version message from new peer: closing %d\n%s", sd, end);
		return false; // no version message, no peer, close connection
	}
	
	// verack
	if (!strncmp(header+CB_MESSAGE_HEADER_TYPE, "verack\0\0\0\0\0\0", 12)) {
		if (peer->versionSent) peer->versionAck = true;
	}
	
	// ping
	else if (!strncmp(header+CB_MESSAGE_HEADER_TYPE, "ping\0\0\0\0\0\0\0\0", 12)) {
		uint64_t nonce = CBByteArrayReadInt64(bytes, 0);
		deb("Nonce: "); deb_hexn((uint8_t *) &nonce, 8);
		send_pong(peer, nonce);
	}
	
	// pong
	else if (!strncmp(header+CB_MESSAGE_HEADER_TYPE, "pong\0\0\0\0\0\0\0\0", 12)) {
		uint64_t nonce = CBByteArrayReadInt64(bytes, 0);
		deb("Nonce: "); deb_hexn((uint8_t *) &nonce, 8);
		peer->connectionWorking = true;
	}
	
	// getblocks
	else if (!strncmp(header+CB_MESSAGE_HEADER_TYPE, "getblocks\0\0\0", 12)) {
		CBGetBlocks *gb = CBNewGetBlocksFromData(bytes);
		CBGetBlocksDeserialise(gb);
		send_inv(peer, gb);
	}

	// inv
	else if (!strncmp(header+CB_MESSAGE_HEADER_TYPE, "inv\0\0\0\0\0\0\0\0\0", 12)) {
		CBInventoryBroadcast *inv = CBNewInventoryBroadcastFromData(bytes);
		CBInventoryBroadcastDeserialise(inv);
		send_getdata(peer, inv);
	}
	
	// getdata
	else if (!strncmp(header+CB_MESSAGE_HEADER_TYPE, "getdata\0\0\0\0\0", 12)) {
		CBInventoryBroadcast *getdata = CBNewInventoryBroadcastFromData(bytes);
		CBInventoryBroadcastDeserialise(getdata);
		send_block(peer, getdata);
	}

	// block
	else if (!strncmp(header+CB_MESSAGE_HEADER_TYPE, "block\0\0\0\0\0\0\0", 12)) {
		CBBlock *block = CBNewBlockFromData(bytes);
		CBBlockDeserialise(block, true);

		CBBlockStatus status = CBFullValidatorProcessBlock(validator, block, time(NULL));
		deb("Block status: ");
		switch (status) {
			case CB_BLOCK_STATUS_MAIN: deb("main"); break;
			case CB_BLOCK_STATUS_SIDE: deb("side"); break;
			case CB_BLOCK_STATUS_ORPHAN: deb("orphan"); break;
			case CB_BLOCK_STATUS_BAD: deb("bad"); break;
			case CB_BLOCK_STATUS_BAD_TIME: deb("bad time"); break;
			case CB_BLOCK_STATUS_DUPLICATE: deb("dupe"); break;
			case CB_BLOCK_STATUS_ERROR: deb("error"); break;
			case CB_BLOCK_STATUS_CONTINUE: deb("continue"); break;
			case CB_BLOCK_STATUS_NO_NEW: deb("no new"); break;
			default: break;
		}
		deb("\n");
		deb("Last validated (main): %d\n", validator->branches[validator->mainBranch].lastValidation);

		CBFreeBlock(block);
	}
	
	// addr
	else if (!strncmp(header+CB_MESSAGE_HEADER_TYPE, "addr\0\0\0\0\0\0\0\0", 12)) {
		CBAddressBroadcast *addr = CBNewAddressBroadcastFromData(bytes, true);
		CBAddressBroadcastDeserialise(addr);
		deb("[addr] count: %d\n", addr->addrNum);

		int i, sd, addr_count = addr->addrNum;
		CBPeer *new_peer;
		CBByteArray *ip;
		CBNetworkAddress *new_addr;
		for (i = 0; i < addr_count; i++) {
			ip = addr->addresses[i]->ip;
			prt_ip(ip); prt("\n");
			/*
			sd = connect_peer(ip->sharedData->data + ip->offset, DEFAULT_PORT);
			if (sd > 0) {
				new_addr = CBNewNetworkAddress(0, addr->addresses[i]->ip, DEFAULT_PORT, CB_SERVICE_FULL_BLOCKS, false);
				new_peer = CBNewPeerByTakingNetworkAddress(new_addr);
				new_peer->socketID = sd;
				new_peer->connectionWorking = true;
				//send_version(new_peer);

				//if (!add_peer(peers, init_peer))
					//prt("Could not insert new kale peer.\n");
			}
			*/
		}

		CBFreeAddressBroadcast(addr);
	}

	deb("%s", end);

	// Clean up
	free(header_p);
	if (length > 24) {
		CBReleaseObject(bytes);
		free(payload);
	}

	return true;
}

int main(int argc, char *argv[]){
#ifdef UMDNET
	prt("Currency: UMD Bitcoin!!!\n");
#endif
	prt("CMSC417: Rudimentary bitcoin client.\n");
	prt("Thach Hoang. 2013.\n");
	help();

	// Delete databases and start anew
	/*
	remove("./blk_log.dat");
	remove("./blk_0.dat");
	remove("./blk_1.dat");
	remove("./blk_2.dat");
	*/

	// Create block validator
	uint64_t storage = CBNewBlockChainStorage("./");
	bool bad;
	validator = CBNewFullValidator(storage, &bad, 0);
	if (!validator || bad) {
		prt("Fail to initialize validator. Sorry...\n");
		return 1;
	}

	// Handle connection errors at send() or recv()
	signal(SIGPIPE, SIG_IGN);

	// Create socket to detect incoming connections
	int listen_sd = listen_at(SELF_PORT);

	// Create list of peers
	peers = malloc(sizeof(CBAssociativeArray));
	if (!peers)
		sysfail("malloc() failed");
	if (!CBInitAssociativeArray(peers, CBKeyCompare, free_peer))
		fail("Could not create associative array for peers.\n");

	// Connect to initial peer
	CBPeer *init_peer = NULL;
	int first_peer_sd = connect_peer(DEFAULT_IP, DEFAULT_PORT);
	if (first_peer_sd > 0) {
		CBByteArray *ip = CBNewByteArrayWithDataCopy(DEFAULT_IP, 16);
		CBNetworkAddress *peeraddr = CBNewNetworkAddress(0, ip, DEFAULT_PORT, CB_SERVICE_FULL_BLOCKS, false);
		init_peer = CBNewPeerByTakingNetworkAddress(peeraddr);
		init_peer->socketID = first_peer_sd;
		init_peer->connectionWorking = true;
		send_version(init_peer);

		CBReleaseObject(ip);
		// Add initial peer to list of peers
		if (!add_peer(init_peer))
			prt("Could not insert first peer.\n");
	}

	int nfds = 0, current_size;
	int new_sd = 0;
	int rv;
	int poll_timeout = PING_INTERVAL * 1000;
	int i, j;
	bool running = true, compress_array = false;
	CBPosition it;
	CBPeer *peer = NULL;

	struct pollfd fds[200]; // TODO heap, expand array if necessary
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
	if (CBAssociativeArrayGetFirst(peers, &it)) {
		do {
			peer = it.node->elements[it.index];
			fds[nfds].fd = peer->socketID;
			fds[nfds].events = POLLIN;
			nfds++;
		} while (!CBAssociativeArrayIterate(peers, &it));
	}

	// The last time we pinged all the peers
	time_t now, diff = 0, last_ping = time(NULL);

	while (running) {
		peer = NULL;

		// Ping all peers
		now = time(NULL);
		if (now - last_ping >= PING_INTERVAL) {
			prt("PING!!! (after %d sec)\n\n", now - last_ping);
			last_ping = now;
			diff = 0;
			// TODO pinging code is noisy; remove on submission
			/*
			if (CBAssociativeArrayGetFirst(peers, &it)) {
				do {
					peer = it.node->elements[it.index];
					if (peer->connectionWorking)
						peer->connectionWorking = false;
					else
						deb("peer at socket %d is silent since last ping.\n", peer->socketID);
					
					if (peer->versionAck)
						send_ping(peer);
				} while (!CBAssociativeArrayIterate(peers, &it));
			}
			*/
		} else {
			diff = now - last_ping;
			//deb("diff: %d, poll: %d\n", diff, PING_INTERVAL - diff);
		}

		// Poll only until the next ping
		poll_timeout = (PING_INTERVAL - diff) * 1000;
		if (poll_timeout < 0)
			poll_timeout = 0;

		rv = poll(fds, nfds, poll_timeout);
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
				prt("Error: revents = %d\n", fds[i].revents);
				running = false;
				break;
			}

			if (fds[i].fd == STDIN_FILENO) {
				// User input
				int rv = command();
				switch (rv) {
					case GETADDR:
						if (init_peer) send_getaddr(init_peer);
						else prt("Initial peer is not available.\n\n");
						break;
					case GETBLOCKS:
						if (init_peer) send_getblocks(init_peer);
						else prt("Initial peer is not available.\n\n");
						break;
					case PING:
						if (init_peer) send_ping(init_peer);
						else prt("Initial peer is not available.\n\n");
						break;
					case STAT:
						prt("Peers: %d\n", peers->root->numElements);
						prt("Last validated (main): %d\n", validator->branches[validator->mainBranch].lastValidation);
						prt("Orphans: %d\n", validator->numOrphans);
						prt("\n");
						break;
					case QUIT:
						prt("Quitting...\n");
						running = false;
						break;
					case VERSION:
						if (init_peer) send_version(init_peer);
						else prt("Initial peer is not available.\n\n");
						break;
					case DEFAULT:
					default:
						break;
				}
			} else if (fds[i].fd == listen_sd) {
				// Listening socket is readable
				// Accept incoming connections: possible new peers
				do {
					// If accept fails with EWOULDBLOCK, then all incoming connections
					// have been accepted. Other failures will end the program.

					// Actual peer object will be created for this connection
					// when the correct version message is received

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
				} while (new_sd != -1);
			} else {
				// Not listening socket. Check other connections.
				peer = NULL;
				bool found = false;
				if (CBAssociativeArrayGetFirst(peers, &it)) {
					do {
						peer = it.node->elements[it.index];
						if (peer->socketID == fds[i].fd) {
							found = true;
							break;
						}
					} while (!CBAssociativeArrayIterate(peers, &it));
				}

				if (!found) peer = NULL;

				bool success = parse_message(fds[i].fd, peer);
				if (!success) {
					deb("Closing %d\n\n", fds[i].fd);
					close(fds[i].fd);
					fds[i].fd = -1;
					compress_array = true;
					if (peer == init_peer)
						init_peer = NULL;
					if (peer)
						CBAssociativeArrayDelete(peers, CBAssociativeArrayFind(peers, peer).position, true);
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
	for (i = 0; i < nfds; i++)
		if (fds[i].fd >= 0)
			close(fds[i].fd);

	CBFreeAssociativeArray(peers);
	free(peers);
	
	CBReleaseObject(validator);
	CBFreeBlockChainStorage(storage);
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

