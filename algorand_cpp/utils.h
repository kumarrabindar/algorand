#pragma once 
#include <string>
#include "blockchain.h"
#include "message.h"

int init_keys_from_response(std::string response, std::string& pk, std::string& sk);
int init_vrf_seed_from_response(std::string response, std::string& seed, std::string& proof);
int init_priority_msg_from_response(std::string response, Priority_Msg* priority_msg, int pid);
int init_block_from_response(std::string response, Block* block, int pid);
int init_committee_vote_msg_from_response(std::string response, Committee_Vote_Msg* committee_vote_msg);
void init_block_of_hash_req_from_response(std::string response, Block_Of_Hash_Request* block_of_hash_req);

void copy_block(Block* dst, Block* src);

int total_token_amount();
