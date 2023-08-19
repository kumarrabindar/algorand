#pragma once 

#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>
#include <map>
#include <bits/stdc++.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>

typedef struct block {
    int round;
    std::string timestamp;
    std::string parent_hash;
    std::string author;
    std::string bp_hash;
    std::string bp_proof;
    std::string seed;
    std::string seed_proof;
    std::string data;

    std::string hash;
} Block;

class Blockchain {
    public:
        Blockchain(std::string pk);
        void add_block(Block* block);
        std::string get_block_seed(int round);
        std::string get_block_hash(int round);
        int num_blocks();

        int last_round;

    private:
        Block* genesis;
        std::map<int, Block*> blocks;
};