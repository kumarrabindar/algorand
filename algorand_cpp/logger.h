#pragma once 

#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>
#include <bits/stdc++.h>
#include <thread>
#include <chrono>
#include <unistd.h>

class Logger {
    public:
        Logger(std::string key, int pid);
        void put(std::string log);

    private:
        std::ofstream logfile;
};