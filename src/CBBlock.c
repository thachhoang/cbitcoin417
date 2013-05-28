//
//  CBBlock.c
//  cbitcoin
//
//  Created by Matthew Mitchell on 01/05/2012.
//  Copyright (c) 2012 Matthew Mitchell
//  
//  This file is part of cbitcoin.
//
//  cbitcoin is free software: you can redistribute it and/or modify
//  it under the terms of the GNU General Public License as published by
//  the Free Software Foundation, either version 3 of the License, or
//  (at your option) any later version.
//  
//  cbitcoin is distributed in the hope that it will be useful, 
//  but WITHOUT ANY WARRANTY; without even the implied warranty of
//  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//  GNU General Public License for more details.
//  
//  You should have received a copy of the GNU General Public License
//  along with cbitcoin.  If not, see <http://www.gnu.org/licenses/>.

//  SEE HEADER FILE FOR DOCUMENTATION

#include "CBBlock.h"

//  Constructor2

CBBlock * CBNewBlock(){
	CBBlock * self = malloc(sizeof(*self));
	if (NOT self) {
		CBLogError("Cannot allocate %i bytes of memory in CBNewBlock\n", sizeof(*self));
		return NULL;
	}
	CBGetObject(self)->free = CBFreeBlock;
	if(CBInitBlock(self))
		return self;
	free(self);
	return NULL;
}
CBBlock * CBNewBlockFromData(CBByteArray * data){
	CBBlock * self = malloc(sizeof(*self));
	if (NOT self) {
		CBLogError("Cannot allocate %i bytes of memory in CBNewBlockFromData\n", sizeof(*self));
		return NULL;
	}
	CBGetObject(self)->free = CBFreeBlock;
	if(CBInitBlockFromData(self, data))
		return self;
	free(self);
	return NULL;
}
CBBlock * CBNewBlockGenesis(){
	CBBlock * self = malloc(sizeof(*self));
	if (NOT self) {
		CBLogError("Cannot allocate %i bytes of memory in CBNewBlockGenesis\n", sizeof(*self));
		return NULL;
	}
	CBGetObject(self)->free = CBFreeBlock;
#ifdef UMDNET
	if(CBInitBlockGenesisUMDNet(self))
#else
	if(CBInitBlockGenesis(self))
#endif
		return self;
	free(self);
	return NULL;
}

//  Object Getter

CBBlock * CBGetBlock(void * self){
	return self;
}

//  Initialiser

bool CBInitBlock(CBBlock * self){
	self->prevBlockHash = NULL;
	self->merkleRoot = NULL;
	self->transactions = NULL;
	self->transactionNum = 0;
	self->hashSet = false;
	memset(self->hash, 0, 32);
	if (NOT CBInitMessageByObject(CBGetMessage(self)))
		return false;
	return true;
}
bool CBInitBlockFromData(CBBlock * self, CBByteArray * data){
	self->prevBlockHash = NULL;
	self->merkleRoot = NULL;
	self->transactions = NULL;
	self->transactionNum = 0;
	self->hashSet = false;
	memset(self->hash, 0, 32);
	if (NOT CBInitMessageByData(CBGetMessage(self), data))
		return false;
	return true;
}
bool CBInitBlockGenesis(CBBlock * self){
	CBByteArray * data = CBNewByteArrayWithDataCopy((uint8_t [285]){0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x3B, 0xA3, 0xED, 0xFD, 0x7A, 0x7B, 0x12, 0xB2, 0x7A, 0xC7, 0x2C, 0x3E, 0x67, 0x76, 0x8F, 0x61, 0x7F, 0xC8, 0x1B, 0xC3, 0x88, 0x8A, 0x51, 0x32, 0x3A, 0x9F, 0xB8, 0xAA, 0x4B, 0x1E, 0x5E, 0x4A, 0x29, 0xAB, 0x5F, 0x49, 0xFF, 0xFF, 0x00, 0x1D, 0x1D, 0xAC, 0x2B, 0x7C, 0x01, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0x4D, 0x04, 0xFF, 0xFF, 0x00, 0x1D, 0x01, 0x04, 0x45, 0x54, 0x68, 0x65, 0x20, 0x54, 0x69, 0x6D, 0x65, 0x73, 0x20, 0x30, 0x33, 0x2F, 0x4A, 0x61, 0x6E, 0x2F, 0x32, 0x30, 0x30, 0x39, 0x20, 0x43, 0x68, 0x61, 0x6E, 0x63, 0x65, 0x6C, 0x6C, 0x6F, 0x72, 0x20, 0x6F, 0x6E, 0x20, 0x62, 0x72, 0x69, 0x6E, 0x6B, 0x20, 0x6F, 0x66, 0x20, 0x73, 0x65, 0x63, 0x6F, 0x6E, 0x64, 0x20, 0x62, 0x61, 0x69, 0x6C, 0x6F, 0x75, 0x74, 0x20, 0x66, 0x6F, 0x72, 0x20, 0x62, 0x61, 0x6E, 0x6B, 0x73, 0xFF, 0xFF, 0xFF, 0xFF, 0x01, 0x00, 0xF2, 0x05, 0x2A, 0x01, 0x00, 0x00, 0x00, 0x43, 0x41, 0x04, 0x67, 0x8A, 0xFD, 0xB0, 0xFE, 0x55, 0x48, 0x27, 0x19, 0x67, 0xF1, 0xA6, 0x71, 0x30, 0xB7, 0x10, 0x5C, 0xD6, 0xA8, 0x28, 0xE0, 0x39, 0x09, 0xA6, 0x79, 0x62, 0xE0, 0xEA, 0x1F, 0x61, 0xDE, 0xB6, 0x49, 0xF6, 0xBC, 0x3F, 0x4C, 0xEF, 0x38, 0xC4, 0xF3, 0x55, 0x04, 0xE5, 0x1E, 0xC1, 0x12, 0xDE, 0x5C, 0x38, 0x4D, 0xF7, 0xBA, 0x0B, 0x8D, 0x57, 0x8A, 0x4C, 0x70, 0x2B, 0x6B, 0xF1, 0x1D, 0x5F, 0xAC, 0x00, 0x00, 0x00, 0x00}, 285);
	if (NOT data)
		return false;
	uint8_t genesisHash[32] = {0x6F, 0xE2, 0x8C, 0x0A, 0xB6, 0xF1, 0xB3, 0x72, 0xC1, 0xA6, 0xA2, 0x46, 0xAE, 0x63, 0xF7, 0x4F, 0x93, 0x1E, 0x83, 0x65, 0xE1, 0x5A, 0x08, 0x9C, 0x68, 0xD6, 0x19, 0x00, 0x00, 0x00, 0x00, 0x00};
	memcpy(self->hash, genesisHash, 32);
	self->hashSet = true;
	if (NOT CBInitMessageByData(CBGetMessage(self), data)){
		CBReleaseObject(data);
		CBReleaseObject(self->hash);
		return false;
	}
	CBReleaseObject(data);
	CBBlockDeserialise(self, true);
	return true;
}

bool CBInitBlockGenesisUMDNet(CBBlock * self){
    CBByteArray * data = CBNewByteArrayWithDataCopy((uint8_t [285]){0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x3b, 0xa3, 0xed, 0xfd, 0x7a, 0x7b, 0x12, 0xb2, 0x7a, 0xc7, 0x2c, 0x3e, 0x67, 0x76, 0x8f, 0x61, 0x7f, 0xc8, 0x1b, 0xc3, 0x88, 0x8a, 0x51, 0x32, 0x3a, 0x9f, 0xb8, 0xaa, 0x4b, 0x1e, 0x5e, 0x4a, 0xb6, 0xf2, 0x70, 0x51, 0xff, 0xff, 0x00, 0x1d, 0xe8, 0x5e, 0x00, 0x00, 0x01, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0x4d, 0x04, 0xff, 0xff, 0x00, 0x1d, 0x01, 0x04, 0x45, 0x54, 0x68, 0x65, 0x20, 0x54, 0x69, 0x6d, 0x65, 0x73, 0x20, 0x30, 0x33, 0x2f, 0x4a, 0x61, 0x6e, 0x2f, 0x32, 0x30, 0x30, 0x39, 0x20, 0x43, 0x68, 0x61, 0x6e, 0x63, 0x65, 0x6c, 0x6c, 0x6f, 0x72, 0x20, 0x6f, 0x6e, 0x20, 0x62, 0x72, 0x69, 0x6e, 0x6b, 0x20, 0x6f, 0x66, 0x20, 0x73, 0x65, 0x63, 0x6f, 0x6e, 0x64, 0x20, 0x62, 0x61, 0x69, 0x6c, 0x6f, 0x75, 0x74, 0x20, 0x66, 0x6f, 0x72, 0x20, 0x62, 0x61, 0x6e, 0x6b, 0x73, 0xff, 0xff, 0xff, 0xff, 0x01, 0x00, 0xf2, 0x05, 0x2a, 0x01, 0x00, 0x00, 0x00, 0x43, 0x41, 0x04, 0x67, 0x8a, 0xfd, 0xb0, 0xfe, 0x55, 0x48, 0x27, 0x19, 0x67, 0xf1, 0xa6, 0x71, 0x30, 0xb7, 0x10, 0x5c, 0xd6, 0xa8, 0x28, 0xe0, 0x39, 0x09, 0xa6, 0x79, 0x62, 0xe0, 0xea, 0x1f, 0x61, 0xde, 0xb6, 0x49, 0xf6, 0xbc, 0x3f, 0x4c, 0xef, 0x38, 0xc4, 0xf3, 0x55, 0x04, 0xe5, 0x1e, 0xc1, 0x12, 0xde, 0x5c, 0x38, 0x4d, 0xf7, 0xba, 0x0b, 0x8d, 0x57, 0x8a, 0x4c, 0x70, 0x2b, 0x6b, 0xf1, 0x1d, 0x5f, 0xac, 0x00, 0x00, 0x00, 0x00}, 285);
    if (NOT data)
        return false;
    uint8_t genesisHash[32] = {0x5c, 0x1d, 0xb6, 0xd5, 0xfe, 0x9b, 0xe8, 0x25, 0x81, 0x43, 0xaf, 0x2c, 0x97, 0xdf, 0xc0, 0xba, 0x46, 0x2d, 0x66, 0x4b, 0xb4, 0x34, 0x54, 0xf1, 0xea, 0xe9, 0xe0, 0x17, 0x00, 0x00, 0x00, 0x00};
    memcpy(self->hash, genesisHash, 32);
    self->hashSet = true;
    if (NOT CBInitMessageByData(CBGetMessage(self), data)){
        CBReleaseObject(data);
        CBReleaseObject(self->hash);
        return false;
    }
    CBReleaseObject(data);
    CBBlockDeserialise(self, true);
    return true;
}


//  Destructor

void CBFreeBlock(void * vself){
	CBBlock * self = vself;
	if(self->prevBlockHash) CBReleaseObject(self->prevBlockHash);
	if(self->merkleRoot) CBReleaseObject(self->merkleRoot);
	if (self->transactions) { // Check for the loop since the transaction number can be set without having any transactions.
		for (uint32_t x = 0; x < self->transactionNum; x++)
			if(self->transactions[x]) CBReleaseObject(self->transactions[x]);
		free(self->transactions);
	}
	if(self->hash) CBReleaseObject(self->hash);
	CBFreeMessage(CBGetObject(self));
}

//  Functions

bool CBBlockCalculateAndSetMerkleRoot(CBBlock * self){
	uint8_t * newRootData = CBBlockCalculateMerkleRoot(self);
	if (NOT newRootData)
		return false;
	CBByteArray * newRoot = CBNewByteArrayWithData(newRootData, 32);
	if (NOT newRoot) {
		free(newRootData);
		return false;
	}
	// Release old merkle root, if it has been previously set.
	if (self->merkleRoot) CBReleaseObject(self->merkleRoot);
	self->merkleRoot = newRoot;
	return true;
}
void CBBlockCalculateHash(CBBlock * self, uint8_t * hash){
	uint8_t * headerData = CBByteArrayGetData(CBGetMessage(self)->bytes);
	uint8_t hash2[32];
	CBSha256(headerData, 80, hash2);
	CBSha256(hash2, 32, hash);
}
uint32_t CBBlockCalculateLength(CBBlock * self, bool transactions){
	uint32_t len = 80 + CBVarIntSizeOf(self->transactionNum);
	if (transactions) {
		for (uint32_t x = 0; x < self->transactionNum; x++)
			len += CBTransactionCalculateLength(self->transactions[x]);
		return len;
	}else return len + 1; // Plus the stupid pointless null byte.
}
uint8_t * CBBlockCalculateMerkleRoot(CBBlock * self){
	uint8_t * txHashes = malloc(32 * self->transactionNum);
	if (NOT txHashes)
		return NULL;
	// Ensure serialisation of transactions and then add their hashes for the calculation
	for (uint32_t x = 0; x < self->transactionNum; x++)
		memcpy(txHashes + 32*x, CBTransactionGetHash(self->transactions[x]), 32);
	CBCalculateMerkleRoot(txHashes, self->transactionNum);
	return txHashes;
}
uint32_t CBBlockDeserialise(CBBlock * self, bool transactions){
	CBByteArray * bytes = CBGetMessage(self)->bytes;
	if (NOT bytes) {
		CBLogError("Attempting to deserialise a CBBlock with no bytes.");
		return 0;
	}
	if (bytes->length < 82) {
		CBLogError("Attempting to deserialise a CBBlock with less than 82 bytes. Minimum for header (With null byte).");
		return 0;
	}
	self->version = CBByteArrayReadInt32(bytes, 0);
	self->prevBlockHash = CBByteArraySubReference(bytes, 4, 32);
	if (NOT self->prevBlockHash){
		CBLogError("Cannot create the previous block hash CBByteArray in CBBlockDeserialise.");
		return 0;
	}
	self->merkleRoot = CBByteArraySubReference(bytes, 36, 32);
	if (NOT self->merkleRoot){
		CBLogError("Cannot create the merkle root CBByteArray in CBBlockDeserialise.");
		return 0;
	}
	self->time = CBByteArrayReadInt32(bytes, 68);
	self->target = CBByteArrayReadInt32(bytes, 72);
	self->nonce = CBByteArrayReadInt32(bytes, 76);
	// If first VarInt byte is zero, then stop here for headers, otherwise look for 8 more bytes and continue
	uint8_t firstByte = CBByteArrayGetByte(bytes, 80);
	if (transactions && firstByte) {
		// More to come
		if (bytes->length < 89) {
			CBLogError("Attempting to deserialise a CBBlock with a non-zero varint with less than 89 bytes.");
			return 0;
		}
		CBVarInt transactionNumVarInt = CBVarIntDecode(bytes, 80);
		if (transactionNumVarInt.val*60 > bytes->length - 81) {
			CBLogError("Attempting to deserialise a CBBlock with too many transactions for the byte data length.");
			return 0;
		}
		self->transactionNum = (uint32_t)transactionNumVarInt.val;
		self->transactions = malloc(sizeof(*self->transactions) * self->transactionNum);
		if (NOT self->transactionNum) {
			CBLogError("Cannot allocate %i bytes of memory in CBBlockDeserialise\n", sizeof(*self->transactions) * self->transactionNum);
			return 0;
		}
		uint32_t cursor = 80 + transactionNumVarInt.size;
		for (uint16_t x = 0; x < self->transactionNum; x++) {
			CBByteArray * data = CBByteArraySubReference(bytes, cursor, bytes->length-cursor);
			if (NOT data) {
				CBLogError("Could not create a new CBByteArray in CBBlockDeserialise for the transaction number %u.", x);
			}
			CBTransaction * transaction = CBNewTransactionFromData(data);
			if (NOT transaction){
				CBLogError("Could not create a new CBTransaction in CBBlockDeserialise for the transaction number %u.", x);
				CBReleaseObject(data);
				return 0;
			}
			uint32_t len = CBTransactionDeserialise(transaction);
			if (NOT len){
				CBLogError("CBBlock cannot be deserialised because of an error with the transaction number %u.", x);
				CBReleaseObject(data);
				return 0;
			}
			// Read just the CBByteArray length
			data->length = len;
			CBReleaseObject(data);
			self->transactions[x] = transaction;
			cursor += len;
		}
		return cursor;
	}else{ // Just header
		uint8_t x;
		if (firstByte < 253) {
			x = 1;
		}else if (firstByte == 253){
			x = 2;
		}else if (firstByte == 254){
			x = 4;
		}else{
			x = 8;
		}
		if (bytes->length < 80 + x + 1) {
			CBLogError("Attempting to deserialise a CBBlock header with not enough space to cover the var int.");
			return 0;
		}
		self->transactionNum = (uint32_t)CBVarIntDecode(bytes, 80).val; // This value is undefined in the protocol. Should best be zero when getting the headers since there is not supposed to be any transactions. Would have probably been better if the var int was dropped completely for headers only.
		// Ensure null byte is null. This null byte is a bit of a nuissance but it exists in the protocol when there are no transactions.
		if (CBByteArrayGetByte(bytes, 80 + x) != 0) {
			CBLogError("Attempting to deserialise a CBBlock header with a final byte which is not null. This is not what it is supposed to be but you already knew that right?");
			return 0;
		}
		return 80 + x + 1; // 80 header bytes, the var int and the null byte
	}
}

uint8_t * CBBlockGetHash(CBBlock * self){
	if (NOT self->hashSet){
		CBBlockCalculateHash(self, self->hash);
		self->hashSet = true;
	}
	return self->hash;
}
uint32_t CBBlockSerialise(CBBlock * self, bool transactions, bool force){
	CBByteArray * bytes = CBGetMessage(self)->bytes;
	if (NOT bytes) {
		CBLogError("Attempting to serialise a CBBlock with no bytes.");
		return 0;
	}
	CBVarInt transactionNum = CBVarIntFromUInt64(self->transactionNum);
	uint32_t cursor = 80 + transactionNum.size;
	if (bytes->length < cursor + 1) {
		CBLogError("Attempting to serialise a CBBlock with less bytes than required for the header, transaction number var int and at least a null byte. %i < %i", bytes->length, cursor + 1);
		return 0;
	}
	// Do header
	CBByteArraySetInt32(bytes, 0, self->version);
	CBByteArrayCopyByteArray(bytes, 4, self->prevBlockHash);
	CBByteArrayChangeReference(self->prevBlockHash, bytes, 4);
	CBByteArrayCopyByteArray(bytes, 36, self->merkleRoot);
	CBByteArrayChangeReference(self->merkleRoot, bytes, 36);
	CBByteArraySetInt32(bytes, 68, self->time);
	CBByteArraySetInt32(bytes, 72, self->target);
	CBByteArraySetInt32(bytes, 76, self->nonce);
	// Do Transactions
	CBVarIntEncode(bytes, 80, transactionNum);
	if (transactions) {
		for (uint32_t x = 0; x < self->transactionNum; x++) {
			if (NOT CBGetMessage(self->transactions[x])->serialised // Serailise if not serialised yet.
				// Serialise if force is true.
				|| force
				// If the data shares the same data as this block, re-serialise the transaction, in case it got overwritten.
				|| CBGetMessage(self->transactions[x])->bytes->sharedData == bytes->sharedData) {
				if (CBGetMessage(self->transactions[x])->serialised)
					// Release old byte array
					CBReleaseObject(CBGetMessage(self->transactions[x])->bytes);
				CBGetMessage(self->transactions[x])->bytes = CBByteArraySubReference(bytes, cursor, bytes->length-cursor);
				if (NOT CBGetMessage(self->transactions[x])->bytes) {
					CBLogError("Cannot create a new CBByteArray sub reference in CBBlockSerialise for the transaction number %u", x);
					return 0;
				}
				if (NOT CBTransactionSerialise(self->transactions[x], force)) {
					CBLogError("CBBlock cannot be serialised because of an error with the transaction number %u.", x);
					return 0;
				}
			}else{
				// Move serialsed data to one location
				if (bytes->length < cursor + CBGetMessage(self->transactions[x])->bytes->length) {
					CBLogError("CBBlock cannot be serialised because there was not enough bytes for the transaction number %u (%u < %u).", x, bytes->length, cursor + CBGetMessage(self->transactions[x])->bytes->length);
					return 0;
				}
				CBByteArrayCopyByteArray(bytes, cursor, CBGetMessage(self->transactions[x])->bytes);
				CBByteArrayChangeReference(CBGetMessage(self->transactions[x])->bytes, bytes, cursor);
			}
			cursor += CBGetMessage(self->transactions[x])->bytes->length;
		}
	}else{
		// Add null byte since there are to be no transactions (header only).
		CBByteArraySetByte(bytes, cursor, 0);
		cursor++;
	}
	// Reset hash
	self->hashSet = false;
	// Ensure data length is correct.
	bytes->length = cursor;
	// Is now serialised.
	CBGetMessage(self)->serialised = true;
	return cursor;
}
