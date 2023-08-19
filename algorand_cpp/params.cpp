#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>
#include <bits/stdc++.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include "params.h"

Params::Params() {}

std::string Params::role(std::string value) {
    if (value == "PROPOSER") {
        return "1";
    } else if (value == "COMMITTEE") {
        return "2";
    } else {
        return "-1";
    }
}

int Params::step(std::string value) {
    if (value == "REDUCTION_ONE") {
        return 1000;
    } else if (value == "REDUCTION_TWO") {
        return 1001;
    } else if (value == "FINAL") {
        return 1002;
    } else if (value == "TENTATIVE") {
        return 1003;
    } else {
        return -1;
    }
}