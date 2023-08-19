#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>
#include <bits/stdc++.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include "message.h"

//std::string delim = "go-algorand";

std::string priority_msg_to_string(Priority_Msg* priority_msg) {
    std::string delim = "go-algorand";

    std::string round = std::to_string(priority_msg->round);
    std::string priority = priority_msg->priority;
    std::string block_hash = priority_msg->block_hash;
    std::string from = priority_msg->from;

    std::string msg = "round:"+round+delim+"priority:"+priority+delim+"block_hash:"+block_hash+
                       delim+"from:"+from;
    return msg;
}

std::string block_to_string(Block* block) {
    std::string delim = "go-algorand";

    std::string round = std::to_string(block->round);
    std::string timestamp = block->timestamp;
    std::string parent_hash = block->parent_hash;
    std::string author = block->author;
    std::string bp_hash = block->bp_hash;
    std::string bp_proof = block->bp_proof;
    std::string seed = block->seed;
    std::string seed_proof = block->seed_proof;
    std::string data = block->data;
    std::string hash = block->hash;

    std::string msg = "round:"+round+delim+"timestamp:"+timestamp+delim+"parent_hash:"+parent_hash+
                      delim+"author:"+author+delim+"bp_hash:"+bp_hash+delim+"bp_proof:"+bp_proof+
                      delim+"seed:"+seed+delim+"seed_proof:"+seed_proof+delim+"data:"+data+delim+
                      "hash:"+hash;
    return msg;
}

std::string committee_vote_msg_to_string(Committee_Vote_Msg* committee_vote_msg) {
    std::string delim = "go-algorand";

    std::string round = std::to_string(committee_vote_msg->round);
    std::string step = std::to_string(committee_vote_msg->step);
    std::string hash = committee_vote_msg->hash;
    std::string proof = committee_vote_msg->proof;
    std::string last_block_hash = committee_vote_msg->last_block_hash;
    std::string value = committee_vote_msg->value;
    std::string from = committee_vote_msg->from;

    std::string msg = "round:"+round+delim+"step:"+step+delim+"hash:"+hash+delim+"proof:"+proof+
                       delim+"last_block_hash:"+last_block_hash+delim+"value:"+value+delim+
                       "from:"+from;
    
    return msg;
}


Message::Message() {}
int Message::message_type(std::string value) {
    if (value == "PRIORITY_MSG") {
        return 1;
    } else if (value == "BLOCK_MSG") {
        return 2;
    } else if (value == "COMMITTEE_VOTE_MSG") {
        return 3;
    } else if (value == "BLOCK_OF_HASH_REQUEST") {
        return 4;
    } else if (value == "BLOCK_OF_HASH_RESPONSE") {
        return 5;
    } else {
        return -1;
    }
}