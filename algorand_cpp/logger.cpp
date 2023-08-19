#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>
#include <bits/stdc++.h>
#include <thread>
#include <chrono>
#include <unistd.h>
#include "logger.h"

Logger::Logger(std::string key, int pid) {
    std::string filename = key + "_" + std::to_string(pid) +".log";
    logfile.open(filename, std::ios::out);
}

void Logger::put(std::string log) {
    logfile << log << std::endl;
}
