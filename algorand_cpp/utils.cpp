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
#include "message.h"
#include "params.h"
#include "common.h"
#include "blockchain.h"


int init_keys_from_response(std::string response, std::string& pk, std::string& sk) {
    printf("[Initiating keys] Response len: %ld\n", response.length());

    std::string delim = "go-algorand";
    int response_len = response.length();

    std::vector<std::string> param_responses;
    while(response.find(delim) != -1) {
        int pos = response.find(delim);
        param_responses.push_back(response.substr(0, pos));
        response = response.substr(pos+delim.length(), response.length());
    }
    param_responses.push_back(response);

    // check success status
    int pos = param_responses[0].find(":");
    std::string param_name = param_responses[0].substr(0, pos);
    std::string param_value = param_responses[0].substr(pos+1, param_responses[0].length());
    if (param_name == "Success" && param_value == "true") {
        // init other params
        for(unsigned int i = 1; i < param_responses.size(); i ++) {
            int pos = param_responses[i].find(":");
            std::string param_name = param_responses[i].substr(0, pos);
            std::string param_value = param_responses[i].substr(pos+1, param_responses[i].length());
            if (param_name == "pk") {
                //std::string temp_pk(param_value, 32);
                //pk = temp_pk;
                pk = param_value;
            } else if (param_name == "sk") {
                //std::string temp_sk(param_value, 64);
                //sk = temp_sk;
                sk = param_value;
            } else {
                printf("[Init KeyPair] Invalid param\n");
                return -1;
            }
        }
        return 0;
    } 
    return -1;
}

int init_vrf_seed_from_response(std::string response, std::string& seed, std::string& proof) {
    std::string delim = "go-algorand";
    int response_len = response.length();

    std::vector<std::string> param_responses;
    while(response.find(delim) != -1) {
        int pos = response.find(delim);
        param_responses.push_back(response.substr(0, pos));
        response = response.substr(pos+delim.length(), response.length());
    }
    param_responses.push_back(response);

    // check success status
    int pos = param_responses[0].find(":");
    std::string param_name = param_responses[0].substr(0, pos);
    std::string param_value = param_responses[0].substr(pos+1, param_responses[0].length());
    if (param_name == "Success" && param_value == "true") {
        // init other params
        for(unsigned int i = 1; i < param_responses.size(); i ++) {
            int pos = param_responses[i].find(":");
            std::string param_name = param_responses[i].substr(0, pos);
            std::string param_value = param_responses[i].substr(pos+1, param_responses[i].length());
            if (param_name == "hash") {
                seed = param_value;
            } else if (param_name == "proof") {
                proof = param_value;
            } else {
                printf("[Init KeyPair] Invalid param\n");
                return -1;
            }
        }
        return 0;
    } 
    return -1;
}

int init_priority_msg_from_response(std::string response, Priority_Msg* priority_msg, int pid) {
    std::string delim = "go-algorand";
    int response_len = response.length();

    std::vector<std::string> param_responses;
    while(response.find(delim) != -1) {
        int pos = response.find(delim);
        param_responses.push_back(response.substr(0, pos));
        response = response.substr(pos+delim.length(), response.length());
    }
    param_responses.push_back(response);
    for(unsigned int i = 0; i < param_responses.size(); i ++) {
        int pos = param_responses[i].find(":");
        std::string param_name = param_responses[i].substr(0, pos);
        std::string param_value = param_responses[i].substr(pos+1, param_responses[i].length());
        if (param_name == "round") {
            priority_msg->round = stoi(param_value);
        } else if (param_name == "block_hash") {
            priority_msg->block_hash = param_value;
        } else if (param_name == "priority") {
            priority_msg->priority = param_value;
        } else if (param_name == "from") {
            priority_msg->from = param_value;
        } else {
            printf("[Priority Msg %d] Invalid Param. Num of params: %d\n", pid, (int)param_responses.size());
            return -1;
        }
    }
    return 0;
}

int init_block_from_response(std::string response, Block* block, int pid) {
    std::string delim = "go-algorand";
    int response_len = response.length();

    std::vector<std::string> param_responses;
    while(response.find(delim) != -1) {
        int pos = response.find(delim);
        param_responses.push_back(response.substr(0, pos));
        response = response.substr(pos+delim.length(), response.length());
    }
    param_responses.push_back(response);
    //printf("[Utils] Number of params: %d\n", (int)param_responses.size());
    for(unsigned int i = 0; i < param_responses.size(); i ++) {
        int pos = param_responses[i].find(":");
        std::string param_name = param_responses[i].substr(0, pos);
        std::string param_value = param_responses[i].substr(pos+1, param_responses[i].length());
        if (param_value != "") {
            if (param_name == "round") {
                block->round = stoi(param_value);
                //block->round = 1;
            } else if (param_name == "timestamp") {
                block->timestamp = param_value;
            } else if (param_name == "parent_hash") {
                block->parent_hash = param_value;
            } else if (param_name == "author") {
                block->author = param_value;
            } else if (param_name == "bp_hash") {
                block->bp_hash = param_value;
            } else if (param_name == "bp_proof") {
                block->bp_proof = param_value;
            } else if (param_name == "seed") {
                block->seed = param_value;
            } else if (param_name == "seed_proof") {
                block->seed_proof = param_value;
            } else if (param_name == "data") {
                block->data = param_value;
            } else if (param_name == "hash") {
                block->hash = param_value;
            } else {
                printf("[Block Msg %d] Invalid Param. Num of params: %d\n", pid, (int)param_responses.size());
                //printf("[Block Msg %d] Invalid Param: %s\n", pid, param_name.c_str());
                return -1;
            }
        }
    }
    return 0;
}

int init_committee_vote_msg_from_response(std::string response, Committee_Vote_Msg* committee_vote_msg) {
    std::string delim = "go-algorand";
    int response_len = response.length();

    std::vector<std::string> param_responses;
    while(response.find(delim) != -1) {
        int pos = response.find(delim);
        param_responses.push_back(response.substr(0, pos));
        response = response.substr(pos+delim.length(), response.length());
    }
    param_responses.push_back(response);

    for(unsigned int i = 0; i < param_responses.size(); i ++) {
        int pos = param_responses[i].find(":");
        std::string param_name = param_responses[i].substr(0, pos);
        std::string param_value = param_responses[i].substr(pos+1, param_responses[i].length());
        if (param_name == "round") {
            committee_vote_msg->round = stoi(param_value);
        } else if (param_name == "step") {
            committee_vote_msg->step = stoi(param_value);
        } else if (param_name == "hash") {
            committee_vote_msg->hash = param_value;
        } else if (param_name == "proof") {
            committee_vote_msg->proof = param_value;
        } else if (param_name == "last_block_hash") {
            committee_vote_msg->last_block_hash = param_value;
        } else if (param_name == "value") {
            committee_vote_msg->value = param_value;
        } else if (param_name == "from") {
            committee_vote_msg->from = param_value;
        } else {
            return -1;
        }
    }
    return 0;
}

void init_block_of_hash_req_from_response(std::string response, Block_Of_Hash_Request* block_of_hash_req) {
    std::string delim = ",";
    int response_len = response.length();

    std::vector<std::string> param_responses;
    while(response.find(delim) != -1) {
        int pos = response.find(delim);
        param_responses.push_back(response.substr(0, pos));
        response = response.substr(pos+delim.length(), response.length());
    }
    param_responses.push_back(response);
    for(unsigned int i = 0; i < param_responses.size(); i ++) {
        int pos = param_responses[i].find(":");
        std::string param_name = param_responses[i].substr(0, pos);
        std::string param_value = param_responses[i].substr(pos+1, param_responses[i].length());
        if (i == 0 && param_name == "Req" && param_value == "BlockOfHash") {
            continue;
        }
        if (param_name == "round") {
            block_of_hash_req->round = stoi(param_value);
        } else if (param_name == "block_hash") {
            block_of_hash_req->block_hash = param_value;
        } else {
            printf("BlockHashReqInitResponse: Invalid Block of Hash request\n");
            return;
        }
    }
}

void copy_block(Block* dst, Block* src) {
    dst->round = src->round;
    dst->timestamp = src->timestamp;
    dst->parent_hash = src->parent_hash;
    dst->author = src->author;
    dst->bp_hash = src->bp_hash;
    dst->bp_proof = src->bp_proof;
    dst->seed = src->seed;
    dst->seed_proof = src->seed_proof;
    //dst->data = src->data;

    dst->hash = src->hash;
}

int total_token_amount() {
    return TOTAL_NUM_PEERS*tokens_per_user;
}