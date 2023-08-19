#pragma once 

#define expected_block_proposers 26   // expected number of block proposers
#define expected_committee_members_step 30  // expected number of committee members for binary ba step
#define expected_committee_members_final 20   // expected number of committee members for final step

#define threshold_committee_step 0.4  // threshold of interactive step 
#define threshold_final_step     0.4   // threshold of final consensus step

#define priority_timeout 1 // original 5
#define block_timeout 2     // original 60
#define step_timeout 1     // original 20
#define block_of_hash_req_timeout 1 // 5 second to receive block of hash from requesting peers

#define MAX_STEPS 13

#define tokens_per_user 100

#define TOTAL_NUM_PEERS 5

#define go_server_port 9002

class Params {
    public:
        Params();

        std::string role(std::string value);
        int step(std::string value);

};