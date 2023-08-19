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
#include <openssl/sha.h>
#include "message.h"


std::string sha256_string(std::string data);
int sub_users(std::string vrf, int expected_users, int weight);
std::string max_priority(std::string vrf, int selected);
std::string hash(Block* block);

std::string current_timestamp();

