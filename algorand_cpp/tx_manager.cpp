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

TxManager::TxManager();
int TxManager::add(std::string hash, Transaction* tx) {
    if (transaction_pool.find(hash) == transaction_pool.end()) {
        return -1;
    }
    transaction_pool[hash] = tx;
    return 0;
}
int TxManager::remove(std::string hash) {
    auto it = transaction_pool.find(hash);
    if (it != transaction_pool.end()) {
        free(it->second);
        transaction_pool.erase(it);
        return 0;
    }
    return -1;
}