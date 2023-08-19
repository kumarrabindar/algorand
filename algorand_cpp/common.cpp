#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>
#include <ctime>
#include <bits/stdc++.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <math.h>
#include <openssl/sha.h>
#include <boost/math/distributions/binomial.hpp>
#include <boost/math/special_functions/beta.hpp>
#include <vrf.h>
#include "common.h"
#include "params.h"
#include "utils.h"
#include "message.h"
#include "constants.h"


std::string sha256_string(std::string data) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, data.c_str(), data.size());
    SHA256_Final(hash, &sha256);
    std::stringstream ss;
    for(int i = 0; i < SHA256_DIGEST_LENGTH; i++)
    {
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
    }
    return ss.str();
}

int sub_users(std::string vrf, int expected_users, int weight) {
    float p = (double)expected_users/(total_token_amount());

    double frac = 0.0;
    for(int i = vrf.length()/3*2; i >= 0; i --) {
        int byte = (int)((unsigned char)vrf[i]);
        frac += (double)(byte) / pow(pow(2, 8), i+1);
    }

    double lower = 0.0;
    double upper = 0.0;

    for(int i = 0; i <= weight; i ++) {
        lower = upper;
        upper += boost::math::ibeta_derivative(i+1, weight-i+1, p) / (weight+1);
        if (lower <= frac && upper > frac) {
            return i;
        }
    }

    return 0;
}

std::string max_priority(std::string vrf, int selected) {
    std::string max_prior;
    for(int i = 1; i <= selected; i ++) {
        std::string prior = sha256_string(vrf + std::to_string(i));
        if (prior > max_prior) {
            max_prior = prior;
        }
    }
    return max_prior;
}

std::string hash(Block* block) {
    std::string res = std::to_string(block->round) + block->timestamp + 
                    block->parent_hash + block->author + block->bp_hash + block->bp_proof + 
                    block->seed + block->seed_proof + block->data; 
    return sha256_string(res);
}


bool verify_msg(std::string pk, std::string proof, std::string m, int go_server_fd) {
    std::string request = "Req:Verify,proof:" + proof + ",m:"+m;
    send(go_server_fd, request.c_str(), request.length(), 0);
    char msg[BUFFER_SIZE];
    memset(msg, '\0', BUFFER_SIZE);
    read(go_server_fd, msg, BUFFER_SIZE);
    // have some doubt here
    if (strcmp(msg, "SUCCESS") == 0) {
        return true;
    }
    return false;
}

std::string current_timestamp() {
    std::time_t t = std::time(0);
    std::stringstream ss;
    ss << t;
    std::string timestamp = ss.str();
    return timestamp;
}