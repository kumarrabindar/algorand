#include <iostream>
#include <ctime>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>
#include <bits/stdc++.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include "blockchain.h"
#include "common.h"

// init blockchain for peer with public key pk
Blockchain::Blockchain(std::string pk) {
    Block* block = (Block*)malloc(sizeof(Block));
    // make sure round 0, genesis block has same seed for all peers
    std::string phrase = "Algorand";
    std::string starting_seed = sha256_string(phrase);

    block->round = 0;
    std::string timestamp = current_timestamp();
    block->timestamp = timestamp;
    block->author = pk;
    block->seed = starting_seed;

    std::string genesis_hash = hash(block);
    block->hash = genesis_hash;

    add_block(block);
  
}

void Blockchain::add_block(Block* block) {
    if (block->round == 0) {
        // genesis block 
        blocks[0] = block;
        last_round = 0;
        return;
    }
    int round = block->round;
    if (round > last_round) {
        blocks[round] = block;
        last_round = round;
        return;
    }
    printf("Block already added for round %d\n", round);
}

std::string Blockchain::get_block_seed(int round) {
    return blocks[round]->seed;
}

std::string Blockchain::get_block_hash(int round) {
    return blocks[round]->hash;
}

int Blockchain::num_blocks() {
    return (int)blocks.size();
}