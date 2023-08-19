#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>
#include <cmath>
#include <bits/stdc++.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <thread>
#include <chrono>
#include <unistd.h>
#include <functional>
#include "peer.h"
#include "transport.h"
#include "blockchain.h"
#include "params.h"
#include "common.h"

int main(int argc, char** argv) {
    int start_port = 9009;
    int num_peers = 5;
    std::vector<std::thread> threads;
    Peer* peers[num_peers];
    Transport* transports[num_peers];
    int ports[num_peers];

    /*
    for(int i = 0; i < num_peers; i ++) {
        ports[i] = start_port+i;
        peers[i] = new Peer(ports[i], tokens_per_user);
        transports[i] = new Transport(ports[i], peers[i]->chain);
    }

    for(int i = 0; i < num_peers; i ++) {
        std::thread transport_listen_t(&Transport::listen_for_peers, transports[i]);
        threads.push_back(move(transport_listen_t));
    }
    // wait for all the transport objects to execute the listen function
    std::this_thread::sleep_for(std::chrono::milliseconds(500));

    // assign transport object to peer
    for(int i = 0; i < num_peers; i ++) {
        peers[i]->dial(transports[i]);
    }

    // let peer connect to other peers
    for(int i = 0; i < num_peers; i ++) {
        peers[i]->connect_to_peers(ports, num_peers);
    }
    
    
    // allow peer to now receive msgs from peers it has connected to
    for(int i = 0; i < num_peers; i ++) {
        std::thread transport_serve_t(&Transport::serve, transports[i]);
        threads.push_back(move(transport_serve_t));
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(500));
    
    for(int i = 0; i < num_peers; i ++) {
        std::thread peer_run_algorand_t(&Peer::run_algorand, peers[i]);
        threads.push_back(move(peer_run_algorand_t));
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(500));

    // join all the threads
    for(unsigned int i = 0; i < threads.size(); i ++) {
        threads[i].join();
    }
    */
    double min_hash = pow(2, 64);
    std::string msg = "Rabindar";
    std::string msg_hash = sha256_string(msg);
    std::hash<std::string> hasher;
    auto hash_value = hasher(msg_hash);
    std::cout << "Min hash value " << min_hash << std::endl;
    std::cout << "Hash value " << hash_value % 2 << std::endl;
}