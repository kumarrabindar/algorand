#pragma once

#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>
#include <bits/stdc++.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include "constants.h"
#include "transport.h"
#include "params.h"
#include "message.h"
#include "blockchain.h"
#include "logger.h"

struct algorand_seed {
    std::string seed;
    std::string proof;
};

struct algorand_sortition {
    std::string hash;
    std::string proof;
    int selected;
};

struct algorand_consensus {
    int type;
    Block* block;
};

class Peer {
    public:
        int tokens_own;
        int pid;
        int go_fd;
        std::string pk;

        Transport* transport;
        Blockchain* chain;
        Message* message;
        Params* params;
        Logger* logger;

        Peer(int id, int tokens_own);
        void run_algorand();

        struct algorand_seed vrf_seed(int round);
        struct algorand_sortition sortition(std::string seed, std::string role, int expected_users);
        Block* propose_block(int round);
        int verify_seed(int round, std::string seed, std::string pk, std::string proof);
        int verify_sortition(std::string pk, std::string hash, std::string proof, std::string seed, std::string role, int expected_value, int weight);
        std::string get_max_priority(int round);
        bool get_max_priority_block(int round, Block* block, std::string cmp_priority);
        struct algorand_consensus execute_ba_star(int round, Block* block);
        std::string binaryBA(int round, std::string block_hash);
        std::string reduction(int round, std::string value); 
        void committee_vote(int round, int step, int expected_members, std::string value);
        std::string count_votes(int round, int step, float threshold, int expected_voters);
        int common_coin(int round, int step, int expected_voters);
        Block* empty_block(int round);
        std::string empty_hash(int round);
        bool validate_block(Block* block);
        void connect_to_peers(int* ports, int num);
        void dial(Transport* transport);

    private:
        int peer_port;
        std::string sk;

        bool connected;
};
