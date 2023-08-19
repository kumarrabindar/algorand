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
#include "blockchain.h"

typedef struct header {
    int msg_type;
    int num_bytes;
} Header;

struct TCP_Msg {
    int type;
    int bytes;
    //char* msg;
    std::string msg;
};

typedef struct priority_msg {
    int round;
    std::string priority;
    std::string block_hash;

    std::string from;
} Priority_Msg;

typedef struct committee_vote_msg {
    int round;
    int step;
    std::string hash;
    std::string proof;
    std::string last_block_hash;
    std::string value;

    std::string from; // sender pk
} Committee_Vote_Msg;

typedef struct block_of_hash_request {
    int round;
    std::string block_hash;
} Block_Of_Hash_Request;


std::string block_to_string(Block* block);
std::string priority_msg_to_string(Priority_Msg* priority_msg);
std::string committee_vote_msg_to_string(Committee_Vote_Msg* committee_vote_msg);

class Message {
    public:
        Message();
        int message_type(std::string value);
};