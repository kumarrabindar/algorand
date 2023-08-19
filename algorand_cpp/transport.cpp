#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>
#include <map>
#include <bits/stdc++.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <unistd.h>
#include "transport.h"
#include "message.h"
#include "constants.h"
#include "utils.h"
#include "params.h"
#include "common.h"
#include "blockchain.h"

Transport::Transport(int port, Blockchain* chain) {
    // init transport object with port and peer
    /*
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
    */
    this->port = port;
    this->chain = chain;
    this->message = new Message();
    this->params = new Params();
    this->logger = new Logger("transport", this->port);
}

void Transport::listen_for_peers() {
    struct sockaddr_in addr;
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        printf("[Transport] Error creating the socket fd...\n");
        exit(-1);
    }

    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(port);

    int status = bind(fd, (struct sockaddr*)&addr, sizeof(addr));
    if (status < 0) {
        printf("[Transport] Error binding the socket fd...\n");
        exit(-1);
    }

    status = listen(fd, 100);
    if (status < 0) {
        printf("[Transport] Error listening to the socket fd...\n");
        exit(-1);
    }

    socklen_t client_len;
    for(;;) { 
        int neighbor_fd = accept(fd, (struct sockaddr*)&addr, &client_len);
        fd_set read_fd_set;
        FD_ZERO(&read_fd_set);
        FD_SET(neighbor_fd, &read_fd_set);
        select(neighbor_fd+1, &read_fd_set, NULL, NULL, NULL);
        if (FD_ISSET(neighbor_fd, &read_fd_set)) {
            char buffer[PUBLIC_KEY_SIZE+1];
            memset(buffer, '\0', PUBLIC_KEY_SIZE+1);
            int pk_size = read(neighbor_fd, buffer, PUBLIC_KEY_SIZE);
            if (pk_size != PUBLIC_KEY_SIZE) {
                printf("Invalid pk on connection\n");
                exit(-1);
            }
            std::string pk = buffer;
            pk_to_fd[pk] = neighbor_fd;
            fd_to_pk[neighbor_fd] = pk;
            // use server fds if want to send msgs to the peers
            // any peer who connects to this server, the fd will be added into the server fds
            send_to_fds.push_back(neighbor_fd);
        }
    }
}

// read msgs on all fd in an infinite loop
void Transport::serve() {
    // check the receive_from_fds to receive messages from the peers you have connected to
    for(;;) {
        fd_set read_fd_set;
        FD_ZERO(&read_fd_set);
        int max_fd = -1;
        for(unsigned int i = 0; i < receive_from_fds.size(); i ++) {
            int fd = receive_from_fds[i];
            if (fd > max_fd) {
                max_fd = fd;
            }
            FD_SET(fd, &read_fd_set);
        }
        select(max_fd+1, &read_fd_set, NULL, NULL, NULL);
        for(unsigned int i = 0; i < receive_from_fds.size(); i ++) {
            int fd = receive_from_fds[i];
            std::string log = "";
            if (FD_ISSET(fd, &read_fd_set)) {
                Header header;
                char packet[9];
                int bytes_read = -1;
                memset(packet, '\0', 9);
                bytes_read = read(fd, packet, 8);
                if (bytes_read != 8) {
                    printf("[Transport] Header not read correctly\n");
                    continue;
                }
                std::memcpy(&header, packet, sizeof(header));
                char buffer[header.num_bytes+1];
                memset(buffer, '\0', header.num_bytes+1);
                bytes_read = read(fd, buffer, header.num_bytes);
                if (bytes_read != header.num_bytes) {
                    printf("[Transport] Msg bytes not read correctly\n");
                    continue;
                }
                std::string response(buffer, bytes_read);
                if (header.msg_type == message->message_type("PRIORITY_MSG")) {
                    Priority_Msg* priority_msg = (Priority_Msg*)malloc(sizeof(Priority_Msg));
                    int status = init_priority_msg_from_response(response, priority_msg, port);
                    if (status == 0) {
                        priority_msgs_per_round[priority_msg->round].push_back(priority_msg);
                        log = "Priority msg buffered";
                        logger->put(log);
                    } else {
                        log = "Invalid Priority Msg";
                        logger->put(log);
                    }
                    
                } else if (header.msg_type == message->message_type("BLOCK_MSG")) {
                    log = "Received block msg";
                    logger->put(log);
                    Block* block = (Block*)malloc(sizeof(Block));
                    //int status = 0;
                    int status = init_block_from_response(response, block, port);
                    if (status == 0) {
                        block_msgs_per_round[block->round].push_back(block);
                        log = "Block msg buffered";
                        logger->put(log);
                    } else if (status == -1) {
                        log = "Invalid block";
                        logger->put(log);
                    }
                    
                } else if (header.msg_type == message->message_type("COMMITTEE_VOTE_MSG")) {
                    Committee_Vote_Msg* committee_vote_msg = (Committee_Vote_Msg*)malloc(sizeof(Committee_Vote_Msg));
                    int status = init_committee_vote_msg_from_response(response, committee_vote_msg);
                    if (status == 0) {
                        int round = committee_vote_msg->round;
                        int step = committee_vote_msg->step;
                        committee_vote_msgs[round][step].push_back(committee_vote_msg);
                        log = "Committee Vote Msg buffered";
                        logger->put(log);
                    }
                } else if (header.msg_type == message->message_type("BLOCK_OF_HASH_REQUEST")) {
                    Block_Of_Hash_Request* block_of_hash_req = (Block_Of_Hash_Request*)malloc(sizeof(Block_Of_Hash_Request));
                    init_block_of_hash_req_from_response(response, block_of_hash_req);
                    block_of_hash_reqs_per_round[block_of_hash_req->round].push_back(block_of_hash_req);
                    send_block_of_hash(fd, block_of_hash_req);
                    // send 
                } else if (header.msg_type == message->message_type("BLOCK_OF_HASH_RESPONSE")) {
                    Block* block = (Block*)malloc(sizeof(Block));
                    init_block_from_response(response, block, port);
                    block_of_hash_responses_per_round[block->round].push_back(block);
                } else {
                    printf("Received invalid header\n");
                }
            }
        }
    }
}

// separate func than send_msg as the request is only to be send to the peers from whom we receive
// the priority whose block hash is the same as the requested block hash
void Transport::send_block_of_hash_request(int round, std::string block_hash) {
    std::vector<Priority_Msg*> msgs = priority_msgs_per_round[round];
    Header header;
    header.msg_type = message->message_type("BLOCK_OF_HASH_REQUEST");
    for(unsigned int i = 0; i < msgs.size(); i ++) {
        Priority_Msg* msg = msgs[i];
        if (msg->block_hash == block_hash) {
            std::string request = "Req:BlockOfHash,round:"+std::to_string(round)+",block_hash:"+block_hash;
            header.num_bytes = request.length();
            int fd = pk_to_fd[msg->from];
            send(fd, &header, sizeof(header), 0);
            send(fd, request.c_str(), request.length(), 0);
        }
    }
}

void Transport::send_block_of_hash(int fd, Block_Of_Hash_Request* block_of_hash_req) {
    int round = block_of_hash_req->round;
    std::string block_hash = block_of_hash_req->block_hash;
    if (buffer_blocks.find(round) == buffer_blocks.end() || buffer_blocks[round]->hash != block_hash) {
        return;
    }
    Block* block = buffer_blocks[round];
    Header header;
    header.msg_type = message->message_type("BLOCK_OF_HASH_RESPONSE");
    std::string response = block_to_string(block);
    header.num_bytes = response.length();
    send(fd, &header, sizeof(header), 0);
    send(fd, response.c_str(), response.length(), 0);
}


void Transport::send_msg(const char* data, int num_bytes) {
    fd_set write_fd_set;
    FD_ZERO(&write_fd_set);
    int max_fd = -1;
    for(unsigned int i = 0; i < send_to_fds.size(); i ++) {
        int fd = send_to_fds[i];
        if (fd > max_fd) {
            max_fd = fd;
        }
        FD_SET(fd, &write_fd_set);
    }
    select(max_fd+1, NULL, &write_fd_set, NULL, NULL);
    for(unsigned int i = 0; i < send_to_fds.size(); i ++) {
        int fd = send_to_fds[i];
        if (FD_ISSET(fd, &write_fd_set)) {
            int bytes_sent = send(fd, data, num_bytes, 0);
            if (bytes_sent != num_bytes) {
                printf("[Transport] Bytes mismatch while sending\n");
            }
        }
    }
}

void Transport::clean(int round) {
    std::vector<Priority_Msg*> priority_msgs = priority_msgs_per_round[round];
    for(unsigned int i = 0; i < priority_msgs.size(); i ++) {
        Priority_Msg* msg = priority_msgs[i];
        free(msg);
    }

    std::vector<Block*> blocks_received = block_msgs_per_round[round];
    for(unsigned int i = 0; i < blocks_received.size(); i ++) {
        Block* msg = blocks_received[i];
        free(msg);
    }

    // clean vote msgs for every round||step, TODO Later
    /*
    std::vector<Committee_Vote_Msg*> vote_msgs = committee_vote_msgs_per_round[round];
    for(unsigned int i = 0; i < vote_msgs.size(); i ++) {
        Committee_Vote_Msg* msg = vote_msgs[i];
        free(msg);
    }
    */
    

    std::vector<Block_Of_Hash_Request*> block_hash_reqs = block_of_hash_reqs_per_round[round];
    for(unsigned int i = 0; i < block_hash_reqs.size(); i ++) {
        Block_Of_Hash_Request* msg = block_hash_reqs[i];
        free(msg);
    }

    std::vector<Block*> block_hash_responses = block_of_hash_responses_per_round[round];
    for(unsigned int i = 0; i < block_hash_responses.size(); i ++) {
        Block* msg = block_hash_responses[i];
        free(msg);
    }
}

void Transport::push_client_fd(int fd) {
    // transport object plays both the roles of the server and the client
    receive_from_fds.push_back(fd);
}

unsigned long Transport::send_to_fds_len() {
    return send_to_fds.size();
}

unsigned long Transport::receive_from_fds_len() {
    return receive_from_fds.size();
}

int Transport::num_priority_msgs(int round) {
    if (priority_msgs_per_round.find(round) == priority_msgs_per_round.end()) {
        return 0;
    }
    return (int)priority_msgs_per_round[round].size();
}

int Transport::num_block_msgs(int round) {
    if (block_msgs_per_round.find(round) == block_msgs_per_round.end()) {
        return 0;
    }
    return (int)block_msgs_per_round[round].size();
}