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
#include "message.h"
#include "params.h"
#include "blockchain.h"
#include "logger.h"

class Transport {
    public:
        int port;
        int go_fd;

        Transport(int port, Blockchain* chain);
        void listen_for_peers();
        void serve();
        void send_msg(const char* data, int num_bytes);
        void send_block_of_hash_request(int round, std::string block_hash);
        void send_block_of_hash(int fd, Block_Of_Hash_Request* block_of_hash_req);

        void clean(int round);
        void push_client_fd(int fd);

        std::map<int, Block*> buffer_blocks;
        std::map<int, std::vector<Block*>> block_of_hash_responses_per_round;

        unsigned long send_to_fds_len();
        unsigned long receive_from_fds_len();
        void setup_msgs(int round);

        int num_priority_msgs(int round);
        int num_block_msgs(int round);

        std::map<int, std::vector<Priority_Msg*>> priority_msgs_per_round;
        std::map<int, std::vector<Block*>> block_msgs_per_round;
        std::map<int, std::map<int, std::vector<Committee_Vote_Msg*>>> committee_vote_msgs;

    private:
        Blockchain* chain;
        Message* message;
        Params* params;
        Logger* logger;
        std::vector<int> neighbors;
        std::vector<int> send_to_fds;   // fds to whom the peeer sends its msg
        std::vector<int> receive_from_fds;  // fds from whome the peer receives other peers msgs
        std::map<std::string, int> pk_to_fd;
        std::map<int, std::string> fd_to_pk;
      
        std::map<int, std::vector<Block_Of_Hash_Request*>> block_of_hash_reqs_per_round;

};

