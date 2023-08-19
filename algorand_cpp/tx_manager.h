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

// two types of transactions are supported. Top up and Transfer. Later add support for external
// world transaction

typedef struct transaction {
    std::string from;
    std::string to;
    int type;
    int amount;
} Transaction;

class TxManager {
    public:
        std::map<std::string, Transaction*> transaction_pool;   // map tx hash -- tx
        int add(std::string hash, Transaction* tx);
        int remove(std::string hash);  
};