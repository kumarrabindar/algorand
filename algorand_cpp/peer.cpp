#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>
#include <ctime>
#include <cmath>
#include <functional>
#include <bits/stdc++.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <thread>
#include <chrono>
#include <vrf.h>
#include "peer.h"
#include "utils.h"
#include "blockchain.h"
#include "common.h"
#include "transport.h"
#include "message.h"
#include "params.h"
#include "logger.h"

Peer::Peer(int id, int tokens_own) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        printf("[Peer] Error creating the socket fd...\n");
        exit(-1);
    }
    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(go_server_port);
    int status = connect(fd, (struct sockaddr*)&addr, sizeof(addr));
    if (status < 0) {
        printf("[Peer] Error connecting to the go server\n");
        exit(-1);
    }
    go_fd = fd;
    std::string req = "Req:KeyPair";
    send(go_fd, req.c_str(), req.size(), 0);
    char buf[BUFFER_SIZE];
    memset(buf, '\0', BUFFER_SIZE);
    int bytes_read = read(go_fd, buf, BUFFER_SIZE);
    std::string response(buf, bytes_read);
    //printf("[KeyPair] Bytes read: %d\n", bytes_read);
    init_keys_from_response(response, pk, sk);
    printf("pk len: %ld, sk len: %ld\n", pk.length(), sk.length());

    this->pid = id;
    this->tokens_own = tokens_own;
    this->chain = new Blockchain(pk);
    this->message = new Message();
    this->params = new Params();
    this->logger = new Logger("peer", pid);
    this->connected = false; 
}

void Peer::dial(Transport* transport) {
    if (!this->connected) {
        this->transport = transport;
        this->connected = true;
        return;
    }
}

void Peer::connect_to_peers(int* ports, int num) {
    for (int i = 0; i < num; i ++) {
        int fd = socket(AF_INET, SOCK_STREAM, 0);
        if (fd < 0) {
            printf("[Peer] Error creating the socket fd...\n");
            return;
        }
        struct sockaddr_in addr;
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = INADDR_ANY;
        addr.sin_port = htons(ports[i]);
        int status = connect(fd, (struct sockaddr*)&addr, sizeof(addr));
        if (status < 0) {
            printf("[Peer] Error connecting to the peer %d...\n", ports[i]);
        } else {
            send(fd, pk.c_str(), pk.size(), 0);
            transport->push_client_fd(fd);
        }
    }
}

struct algorand_seed Peer::vrf_seed(int round) {
    // get the seed of previous round 
    std::string log = "";
    std::string delim = "go-algorand";
    std::string seed = chain->get_block_seed(round-1);
    std::string message = seed + std::to_string(round);
    std::string req = "Req:Evaluate"+delim+"m:"+message+delim+"pk:"+pk+delim+"sk:"+sk;
    int bytes_sent = send(go_fd, req.c_str(), req.size(), 0);
    log = "Vrf seed. Bytes sent: " + std::to_string(bytes_sent);
    logger->put(log);
    char buf[BUFFER_SIZE];
    memset(buf, '\0', BUFFER_SIZE);
    int bytes_read = read(go_fd, buf, BUFFER_SIZE);
    std::string response(buf, bytes_read);
    log = "Bytes read: " + std::to_string(bytes_read);
    logger->put(log);
    struct algorand_seed round_seed;
    // assum status = 0
    init_vrf_seed_from_response(response, round_seed.seed, round_seed.proof);
    log = "Seed generated. Round: " + std::to_string(round) + ", seed: " + 
          std::to_string((int)round_seed.seed.size()) + ", seed proof: " + 
          std::to_string((int)round_seed.proof.size());
    logger->put(log);

    return round_seed;
}

// only use sortition for prescriped roles in algorand
// only called by a user to generate hash, proof, sub-selected
struct algorand_sortition Peer::sortition(std::string seed, std::string role, int expected_users) {
    std::string log = "";
    std::string delim = "go-algorand";
    std::string message = seed + role;
    std::string req = "Req:Evaluate"+delim+"m:"+message+delim+"pk:"+pk+delim+"sk:"+sk;
    send(go_fd, req.c_str(), req.size(), 0);
    char buf[BUFFER_SIZE];
    memset(buf, '\0', BUFFER_SIZE);
    int bytes_read = read(go_fd, buf, BUFFER_SIZE);
    std::string response(buf, bytes_read);
    log = "Bytes read: " + std::to_string(bytes_read);
    logger->put(log);
    struct algorand_sortition sortition_res;
    // assum status = 0
    init_vrf_seed_from_response(response, sortition_res.hash, sortition_res.proof);
    log = "Sortition. Role: " + role + ", hash: " + 
          std::to_string((int)sortition_res.hash.size()) + ", proof: " + 
          std::to_string((int)sortition_res.proof.size());
    logger->put(log);

    sortition_res.selected = sub_users(sortition_res.hash, expected_users, tokens_own);
    return sortition_res;
}

void Peer::run_algorand() {
    // wait for some time for all peers to get ready
    std::this_thread::sleep_for(std::chrono::milliseconds(500));
    int round = chain->last_round + 1;
    std::string log = "";
    int num_send_fds = (int)transport->send_to_fds_len();
    int num_receive_fds = (int)transport->receive_from_fds_len();
    log = "Running algorand. Round: "+std::to_string(round)+", Send Fds: "+std::to_string(num_send_fds) +
        ", Receive Fds: "+std::to_string(num_receive_fds);
    logger->put(log);
    Block* block = propose_block(round);
    log = "Proposed block: " + block->hash;
    logger->put(log);
    printf("[Peer] %d proposed block %s\n", pid, block->hash.c_str());
    struct algorand_consensus consensus = execute_ba_star(round, block);
    printf("[Peer] %d reached %d consensus on block %s\n", pid, consensus.type, consensus.block->hash.c_str());
    //for(;;) {
    //  
    //}
    /*
    // block has been proposed for this round by peer
    transport->buffer_blocks[round] = block;
    struct algorand_consensus consensus = execute_ba_star(round, block);
    std::string response = block_to_string(consensus.block);
    if (consensus.type == params->step("FINAL")) {
        printf("Reached FINAL Consensus on block. Block: %s\n", response.c_str());
    } else {
        printf("Reached TENTATIVE Consensus on block. Block: %s\n", response.c_str());
    }
    transport->clean(round);
    printf("Round %d finished\n", chain->last_round + 1);
    
    // Complete rest of the logics later
    */
}

Block* Peer::propose_block(int round) {
    std::string log = "";
    std::string seed = chain->get_block_seed(round-1);
    struct algorand_sortition sortition_res = sortition(seed, params->role("PROPOSER"), expected_block_proposers);
    Block* block = (Block*)malloc(sizeof(Block));
    bool final_proposer = false;
    std::string priority = "";
    if (sortition_res.selected > 0) {
        log  = "Selected for block proposal for round: " + std::to_string(round);
        logger->put(log);
        struct algorand_seed next_round_seed;
        next_round_seed = vrf_seed(round);

        block->round = round;
        std::string timestamp = current_timestamp();

        block->timestamp = timestamp;
        block->parent_hash = chain->get_block_hash(round-1);
        block->author = pk;

        block->bp_hash = sortition_res.hash;
        block->bp_proof = sortition_res.proof;
        block->seed = next_round_seed.seed;
        block->seed_proof = next_round_seed.proof;
        block->hash = hash(block);

        Priority_Msg priority_msg;
        priority_msg.round = round;
        priority_msg.priority = max_priority(sortition_res.hash, sortition_res.selected);
        priority_msg.block_hash = block->hash;
        priority_msg.from = pk;

        priority = priority_msg.priority;
        log = "Peer priority: " + priority;
        logger->put(log);

        std::string msg = priority_msg_to_string(&priority_msg);

        Header header;
        header.msg_type = message->message_type("PRIORITY_MSG");
        header.num_bytes = msg.length();
        char* header_bytes = (char*)&header;
        std::string header_string(header_bytes, 8);
        std::string final_msg = header_string+msg;
        log = "Sending TCP Priority Msg. Header Bytes: " + std::to_string((int)header_string.length()) + 
              ", Msg Bytes: " + std::to_string((int)msg.length()) + ", Final Msg Bytes: " + std::to_string((int)final_msg.length());
        logger->put(log);
        transport->send_msg(final_msg.c_str(), (int)final_msg.length());
    } else {
        log = "Round: " + std::to_string(round) + ", Not selected for block proposal";
        logger->put(log);
    }
    
    // wait for priority timeout before receiving the max priority
    std::this_thread::sleep_for(std::chrono::seconds(priority_timeout));
    log = "Number of priority msgs received: " + std::to_string(transport->num_priority_msgs(round));
    logger->put(log);
    std::string max_priority = get_max_priority(round);
    log = "Max Priority received: " + max_priority;
    logger->put(log);

    // TODO: Put data inside the block
    if (sortition_res.selected > 0 && priority >= max_priority) {
        final_proposer = true;
        std::string msg = block_to_string(block);
        Header header;
        header.msg_type = message->message_type("BLOCK_MSG");
        header.num_bytes = msg.length();
        char* header_bytes = (char*)&header;
        std::string header_string(header_bytes, 8);
        std::string final_msg = header_string+msg;
    
        log = "[Peer] Sending TCP Block Msg. Header Bytes: " + std::to_string((int)header_string.length()) + 
              ", Msg Bytes: " + std::to_string((int)msg.length()) + ", Final Msg Bytes: " + std::to_string((int)final_msg.length());
        logger->put(log);
        transport->send_msg(final_msg.c_str(), (int)final_msg.length());
        log = "Sent Block Msg";
        logger->put(log);
    }

    // wait for block timeout before receving the max prior block
    std::this_thread::sleep_for(std::chrono::seconds(block_timeout));
    if (!final_proposer) {
        log = "Number of block msgs received: " + std::to_string((int)transport->num_block_msgs(round));
        logger->put(log);
        bool res = get_max_priority_block(round, block, max_priority);
        if (res) {
            log = "Got max priority block";
            logger->put(log);
        } else {
            log = "Proposing empty block";
            logger->put(log);
            free(block);
            block = empty_block(round);
        }
    }
    
    return block; 
}

std::string Peer::get_max_priority(int round) {
    std::string max_priority = "";
    if(transport->priority_msgs_per_round.find(round) == transport->priority_msgs_per_round.end()) {
        return max_priority;
    }
    std::vector<Priority_Msg*> msgs = transport->priority_msgs_per_round[round];
    for(unsigned int i = 0; i < msgs.size(); i ++) {
        Priority_Msg* msg = msgs[i];
        if (max_priority == "" || msg->priority > max_priority) {
            max_priority = msg->priority;
        }
    }
    return max_priority;
}


bool Peer::get_max_priority_block(int round, Block* block, std::string cmp_priority) {
    if (transport->block_msgs_per_round.find(round) == transport->block_msgs_per_round.end()) {
        return false;
    }
    std::string log = "";
    std::vector<Block*> msgs = transport->block_msgs_per_round[round];
    for(unsigned int i = 0; i < msgs.size(); i ++) {
        Block* msg = msgs[i];
        std::string seed = chain->get_block_seed(round-1);
        int status = verify_seed(round, seed, msg->author, msg->seed_proof);
        if (status == -1) {
            continue;
        }
        int selected = verify_sortition(msg->author, msg->bp_hash, msg->bp_proof, seed, params->role("PROPOSER"), expected_block_proposers, tokens_per_user);
        if (selected > 0) {
            std::string priority = max_priority(msg->bp_hash, selected);
            if (priority >= cmp_priority) {
                copy_block(block, msg);
                log = "Max priority block init";
                logger->put(log);
                return true;
            }
        }
    }
    return false;
}

int Peer::verify_seed(int round, std::string seed, std::string pk, std::string proof) {
    std::string log = "";
    std::string message = seed+std::to_string(round);
    std::string delim = "go-algorand";
    log = "Sending verify seed request. pk: " + std::to_string((int)pk.size()) +
          ", proof: " + std::to_string((int)proof.size()) + ", m: " + std::to_string((int)message.size());
    logger->put(log);
    std::string req = "Req:Verify"+delim+"pk:"+pk+delim+"proof:"+proof+delim+"m:"+message;
    log = "Verify seed request size: " + std::to_string((int)req.size());
    logger->put(log);
    send(go_fd, req.c_str(), req.size(), 0);
    char buf[BUFFER_SIZE];
    memset(buf, '\0', BUFFER_SIZE);
    int bytes_read = read(go_fd, buf, BUFFER_SIZE);
    log = "Verify seed bytes read: " + std::to_string(bytes_read);
    logger->put(log);
    std::string response(buf, bytes_read);
    if (response == "Success:true") {
        return 0;
    }
    return -1;
}

Block* Peer::empty_block(int round) {
    Block* block = (Block*)malloc(sizeof(Block));
    block->round = round;
    block->parent_hash = chain->get_block_hash(round-1);
    block->seed = sha256_string(chain->get_block_seed(round-1)+std::to_string(round));

    block->hash = hash(block);

    return block;
}


int Peer::verify_sortition(std::string pk, std::string hash, std::string proof, std::string seed, std::string role, int expected_value, int weight) {
    std::string log = "";
    std::string delim = "go-algorand";
    std::string message = seed + role;
    log = "Sending verify sortitionr request. pk: " + std::to_string((int)pk.size()) +
          ", proof: " + std::to_string((int)proof.size()) + ", m: " + std::to_string((int)message.size());
    logger->put(log);
    //std::string message = seed + role;
    std::string req = "Req:Verify"+delim+"pk:"+pk+delim+"proof:"+proof+delim+"m:"+message;
    log = "Verify sortition request size: " + std::to_string((int)req.size());
    logger->put(log);
    send(go_fd, req.c_str(), req.size(), 0);
    char buf[BUFFER_SIZE];
    memset(buf, '\0', BUFFER_SIZE);
    int bytes_read = read(go_fd, buf, BUFFER_SIZE);
    log = "Verify sortition bytes read: " + std::to_string(bytes_read);
    logger->put(log);
    std::string response(buf, bytes_read);
    //std::string log = "";
    log = "Verification sortition response: " + response;
    logger->put(log);

    if (response == "Success:true") {
        return sub_users(hash, expected_value, weight);
    }
    return -1;
}


struct algorand_consensus Peer::execute_ba_star(int round, Block* block) {
    // asynchornous execution of this function
    // execute reduction to get the block
    std::string log = "";
    log = "BA* initiated with " + block->hash;
    logger->put(log);
    struct algorand_consensus consensus;
    std::string value = reduction(round, block->hash);
    log = "Reduction value: " + value;
    logger->put(log);
    value = binaryBA(round, value);
    std::this_thread::sleep_for(std::chrono::seconds(step_timeout));
    std::string final_value = count_votes(round, params->step("FINAL"), threshold_final_step, expected_committee_members_final);
    // sleep for some time
    if (final_value == value && value == block->hash) {
        consensus.type = params->step("FINAL");
        consensus.block = block;
        return consensus;
    }
    consensus.type = -1;
    consensus.block = block;
    return consensus;

    /*
    if (final_value == value) {
        consensus.type = params->step("FINAL");
        consensus.block = NULL;
    } else if (value == block->hash) {
        consensus.type = params->step("TENTATIVE");
        consensus.block = block;
    } else {
        consensus.type = params->step("TENTATIVE");
        consensus.block = NULL;
    }

    if (consensus.block == NULL) {
        transport->send_block_of_hash_request(round, value);
        std::this_thread::sleep_for(std::chrono::seconds(block_of_hash_req_timeout));
        if (transport->block_of_hash_responses_per_round[round].size() > 0) {
            // block has been received
            consensus.block = transport->block_of_hash_responses_per_round[round][0];
        }
    }
    if (consensus.block == NULL) {
        empty_block(round, block);
        consensus.block = block;
    }
    return consensus;
    */
}

std::string Peer::binaryBA(int round, std::string block_hash) {
    std::string log = "";
    log = "Initiated binary BA with " + block_hash;
    logger->put(log);
    std::string empty_value = empty_hash(round);
    int step = 1;
    std::string r = block_hash;
    while(step < MAX_STEPS) {
        committee_vote(round, step, expected_committee_members_step, r);
        std::this_thread::sleep_for(std::chrono::seconds(step_timeout));
        r = count_votes(round, step, threshold_committee_step, expected_committee_members_step);
        if (r == "") {
            // timeout, try for one more time in next step
            r = block_hash;
        } else if (r != empty_value) {
            // value agreed
            // send committee votes for step+3
            int s = step+1;
            int e = step+3;
            while(s <= e) {
                committee_vote(round, s, expected_committee_members_step, r);
                s += 1;
            }
            if (step == 1) {
                // for BA* to check if the returned r is the FINAL OR TENTATIVE consensus
                committee_vote(round, params->step("FINAL"), expected_committee_members_final, r);
            }
            return r;
        }

        // try to send committee vote for r one more time
        step += 1;
        committee_vote(round, step, expected_committee_members_step, r);
        std::this_thread::sleep_for(std::chrono::seconds(step_timeout));
        r = count_votes(round, step, threshold_committee_step, expected_committee_members_step);
        if (r == "") {
            // timeout, repeat committee votes on empty_hash_value
            r = empty_value;
        } else if (r == empty_value) {
            // user has reached tentative consensus on empty_hash_value
            int s = step+1;
            int e = step+3;
            while(s <= e) {
                committee_vote(round, s, expected_committee_members_step, r);
                s += 1;
            }
            return r;
        }

        step += 1;
        committee_vote(round, step, expected_committee_members_step, r);
        std::this_thread::sleep_for(std::chrono::seconds(step_timeout));
        r = count_votes(round, step, threshold_committee_step, expected_committee_members_step);
        if (r == ""){
            // timeout, use common coin to select the value of r
            int bit = common_coin(round, step, expected_committee_members_step);
            if (bit == 0) {
                r = block_hash;
            } else {
                r = empty_value;
            }
        }
        // assume no timeout here, later implement common coin
        step += 1;
    }
    // hang forever
    return "";
}

std::string Peer::reduction(int round, std::string value) {
    std::string log = "";
    log = "executing reduction step one";
    logger->put(log);
    committee_vote(round, params->step("REDUCTION_ONE"), expected_committee_members_step, value);
    std::this_thread::sleep_for(std::chrono::seconds(block_timeout+step_timeout));
    std::string popular_value = count_votes(round, params->step("REDUCTION_ONE"), threshold_committee_step, expected_committee_members_step);
    std::string empty_value = empty_hash(round);

    if (popular_value == "") {
        // timeout, set value as empty value
        log = "reduction timeout step one";
        logger->put(log);
        value = empty_value;
    } else {
        // set value as popular value
        value = popular_value;
    }
    log = "executing reduction step two";
    logger->put(log);
    committee_vote(round, params->step("REDUCTION_TWO"), expected_committee_members_step, value);
    std::this_thread::sleep_for(std::chrono::seconds(block_timeout+step_timeout));
    // wait for some time and then receive all the votes;
    popular_value = count_votes(round, params->step("REDUCTION_TWO"), threshold_committee_step, expected_committee_members_step);
    if (popular_value == "") {
        //printf("[Peer] Reduction timeout step twp\n");
        log = "reduction timeout step two";
        logger->put(log);
        return empty_value;
    }
    return popular_value;
}

void Peer::committee_vote(int round, int step, int expected_members, std::string value) {
    std::string role = "COMMITTEE" + std::to_string(round) + std::to_string(step);
    std::string seed = chain->get_block_seed(round-1);
    struct algorand_sortition res;
    res = sortition(seed, role, expected_members);
    std::string log = "";
    if (res.selected > 0) {
        log = "Selected for committe vote for round: " + std::to_string(round) + ", step: " + 
               std::to_string(step) + ", hash: " + std::to_string((int)res.hash.size()) + 
               ", proof: " + std::to_string((int)res.proof.size());
        logger->put(log);
        std::string last_block_hash = chain->get_block_hash(round-1);
        
        Committee_Vote_Msg committee_vote_msg;
        committee_vote_msg.round = round;
        committee_vote_msg.step = step;
        committee_vote_msg.hash = res.hash;
        committee_vote_msg.proof = res.proof;
        committee_vote_msg.last_block_hash = last_block_hash;
        committee_vote_msg.value = value;

        committee_vote_msg.from = pk;

        std::string msg = committee_vote_msg_to_string(&committee_vote_msg);

        Header header;
        header.msg_type = message->message_type("COMMITTEE_VOTE_MSG");
        header.num_bytes = msg.length();
        char* header_bytes = (char*)&header;
        std::string header_string(header_bytes, 8);
        std::string final_msg = header_string+msg;
    
        //log = "[Peer] Sending TCP Committee Vote Msg. Header Bytes: " + std::to_string((int)header_string.length()) + 
        //      ", Msg Bytes: " + std::to_string((int)msg.length()) + ", Final Msg Bytes: " + std::to_string((int)final_msg.length());
        //logger->put(log);
        transport->send_msg(final_msg.c_str(), (int)final_msg.length());
    } else {
        log = "Not selected for committe vote for round: " + std::to_string(round) + ", step: " + 
               std::to_string(step);
        logger->put(log);
    }
}


std::string Peer::count_votes(int round, int step, float threshold, int expected_voters) {
    if (transport->committee_vote_msgs.find(round) == transport->committee_vote_msgs.end()) {
        return "";
    }

    if (transport->committee_vote_msgs[round].find(step) == transport->committee_vote_msgs[round].end()) {
        return "";
    }

    std::string log = "";
    std::vector<Committee_Vote_Msg*> msgs = transport->committee_vote_msgs[round][step];
    log = "Counting votes for round: " + std::to_string(round) + ", step: " + std::to_string(step) +
          ", number of msgs: " + std::to_string((int)msgs.size());
    logger->put(log);
    std::string seed = chain->get_block_seed(round-1);
    std::string role = "COMMITTEE" + std::to_string(round) + std::to_string(step);

    std::map<std::string, int> votes;   // map(value, number of votes)
    std::map<std::string, std::string> voters;  // map(pk, value)
    
    for(unsigned int i = 0; i < msgs.size(); i ++) {
        Committee_Vote_Msg* msg = msgs[i];
        int j = verify_sortition(msg->from, msg->hash, msg->proof, seed, role, expected_voters, tokens_per_user);
        // chain->get_block_hash(round-1) == msg->last_block_hash, only if round > 1
        if (j > 0 && voters.find(msg->from) == voters.end()) {
            voters[msg->from] = msg->value;
            if (votes.find(msg->value) == votes.end()) {
                votes[msg->value] = j;
            } else {
                votes[msg->value] += j;
            }
        }
    }

    // iterate all the values in votes map and check if any value received >= threshold votes
    for(std::map<std::string, int>::iterator iter = votes.begin(); iter != votes.end(); iter ++) {
        std::string value = iter->first;
        int total_votes = votes[value];
        int votes_threshold = (int)(threshold*expected_voters+0.5);
        log = "Round: " + std::to_string(round) + "Step: " + std::to_string(step) + "Value: " + 
               value + ", Votes received: " + std::to_string(total_votes) + ", threshold: " + 
               std::to_string(votes_threshold);
        logger->put(log);
        if (total_votes >= votes_threshold) {
            return value;
        }
    }

    return "";
}

int Peer::common_coin(int round, int step, int expected_voters) {
    if (transport->committee_vote_msgs.find(round) == transport->committee_vote_msgs.end()) {
        return 0;
    }

    if (transport->committee_vote_msgs[round].find(step) == transport->committee_vote_msgs[round].end()) {
        return 0;
    }

    double min_hash = pow(2, 64);
    std::vector<Committee_Vote_Msg*> msgs = transport->committee_vote_msgs[round][step];
    std::string seed = chain->get_block_seed(round-1);
    std::string role = "COMMITTEE" + std::to_string(round) + std::to_string(step);
    for(unsigned int i = 0; i < msgs.size(); i ++) {
        Committee_Vote_Msg* msg = msgs[i];
        int j = verify_sortition(msg->from, msg->hash, msg->proof, seed, role, expected_voters, tokens_per_user);
        if (j > 0) {
            for(int i = 1; i <= j; i ++) {
                std::string h = sha256_string(msg->hash+std::to_string(i));
                std::hash<std::string> hasher;
                double hash_value = (double)hasher(h);
                if(hash_value < min_hash) {
                    min_hash = hash_value;
                }
            }
        }
    }
    return (int)std::fmod(min_hash, 2.0);
}


std::string Peer::empty_hash(int round) {
    Block block;
    block.round = round;
    block.parent_hash = chain->get_block_hash(round-1);
    block.seed = sha256_string(chain->get_block_seed(round-1)+std::to_string(round));
    block.author = pk;

    block.hash = hash(&block);
    return block.hash;
}