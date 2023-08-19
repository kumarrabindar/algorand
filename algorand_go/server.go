package main

import (
	"log"
	"fmt"
	"strings"
	"net"
	//"bytes"

	"algorand_go/vrf"
	//"algorand_go/binomial"
)


func main() {
	server, err := net.Listen("tcp", "127.0.0.1:9002");
	fmt.Println("Server listening on 9002");
	//go test_server();
	if err != nil {
		log.Fatal(err);
	}
	counter := 0;
	for {
		conn, err := server.Accept();
		counter += 1;
		if err != nil {
			log.Fatal(err);
		}
		//fmt.Println("Client connected");
		go handleConn(conn, counter);
		if err != nil {
			log.Fatal(err);
		}
	}

	//selected := test_sub_users();
	//fmt.Println(selected);

}

/*
func test_sub_users(vrf []byte) int {
	weight := 100;
	expectedNum := 3;
	TotalTokenAmount := 500;
	bino := binomial.NewFastBinomial(int64(weight), float64(expectedNum)/float64(TotalTokenAmount))
	
	
	frac := 0.0
	for i := len(vrf) / 3 * 2; i >= 0; i-- {
		frac += float64(vrf[i]) / float64(math.Pow(math.Pow(2, 8), float64(i+1)))
	}

	lower := 0.0
	upper := 0.0
	for i := uint64(0); i <= uint64(weight); i++ {
		lower = upper
		upper += bino.Prob(int64(i))
		if lower <= frac && upper > frac {
			fmt.Println(lower, upper);
			return int(i)
		}
	}

	return 0
}
*/


/*
func test_server() {
	time.Sleep(10*time.Millisecond);
	conn, err := net.Dial("tcp", "127.0.0.1:9002");
	if (err != nil) {
		log.Fatal(err);
	}
	time.Sleep(1*time.Second);
	conn.Close();
}
*/

/*
func test_vrf() {
	pk, sk := vrf.NewKeyPair();
	m := []byte("Hello world");
	hash, proof := vrf.Evaluate(m, pk, sk);
	fmt.Println(hash, proof);

	status, err := vrf.Verify(pk, proof, m);
	fmt.Println(status, err);
}
*/

func handleConn(conn net.Conn, client_id int) {
	delim := "go-algorand";
	for {
		// listen for the requests from the client
		// read header 8 bytes first
		request_bytes := make([]byte, 512);
		n, _ := conn.Read(request_bytes);
		if (n == 0) {
			return;
		}
		var param_responses []string;
		request := string(request_bytes[:n]);
		for (strings.Index(request, delim) != -1) {
			pos := strings.Index(request, delim);
			param_responses = append(param_responses, request[:pos]);
			request = request[pos+len(delim):];
		}

		param_responses = append(param_responses, request);
		pos := strings.Index(param_responses[0], ":");
		//param_name := param_responses[0][:pos];
		param_value := param_responses[0][pos+1:];
		switch param_value {
			case "KeyPair":
				pk, sk := vrf.NewKeyPair();
				pk_str := string(pk);
				sk_str := string(sk);
				msg := "Success:true"+delim+"pk:"+pk_str+delim+"sk:"+sk_str;
				n, _ = conn.Write([]byte(msg));
				break;
			
			case "Evaluate":
				//pk_init := false;
				pk_str := "";
				//sk_init := false;
				sk_str := "";
				//m_init := false;
				m_str := "";

				msg := "";

				for i := 1; i < len(param_responses); i ++ {
					pos := strings.Index(param_responses[i], ":");
					param_name := param_responses[i][:pos];
					param_value := param_responses[i][pos+1:];
					
					switch param_name {
						case "m":
							m_str = param_value;
							//m_init = true;
							break;
						
						case "pk":
							pk_str = param_value;
							//pk_init = true;
							break;

						case "sk":
							sk_str = param_value;
							//sk_init = true;
							break;
						
						default:
							break;
						
					}
				}

				if (len(pk_str) == 32 && len(sk_str) == 64) {
					// /fmt.Printf("pk: %d, sk: %d, m: %d\n", len(pk), len(sk), len(m));
					hash, proof := vrf.Evaluate([]byte(m_str), []byte(pk_str), []byte(sk_str));
					msg = "Success:true"+delim+"hash:"+string(hash)+delim+"proof:"+string(proof);
				} else {
					fmt.Println("Evaluate request unsuccessful");
					msg = "Success:false";
				}

				conn.Write([]byte(msg));
				break;
			
			case "Verify":
				//pk_init := false;
				pk_str := "";
				//proof_init := false;
				proof_str := "";
				//m_init := false;
				m_str := "";

				msg := "";

				for i := 1; i < len(param_responses); i ++ {
					pos := strings.Index(param_responses[i], ":");
					param_name := param_responses[i][:pos];
					param_value := param_responses[i][pos+1:];
					
					switch param_name {
						case "m":
							m_str = param_value;
							//m_init = true;
							break;
						
						case "pk":
							pk_str = param_value;
							//pk_init = true;
							break;

						case "proof":
							proof_str = param_value;
							//proof_init = true;
							break;
						
						default:
							break;
						
					}
				}

				if (len(pk_str) == 32 && len(proof_str) == 81) {
					status := vrf.Verify([]byte(pk_str), []byte(proof_str), []byte(m_str));
					if (status) {
						msg = "Success:true";
					} else {
						msg = "Success:false";
					}
				}

				conn.Write([]byte(msg));
				break;
			
			default:
				break;

		}

		/*

			std::string delim = "go-algorand";
			int response_len = response.length();

			std::vector<std::string> param_responses;
			while(response.find(delim) != -1) {
				int pos = response.find(delim);
				param_responses.push_back(response.substr(0, pos));
				response = response.substr(pos+delim.length(), response.length());
			}
			param_responses.push_back(response);

			// check success status
			int pos = param_responses[0].find(":");
			std::string param_name = param_responses[0].substr(0, pos);
			std::string param_value = param_responses[0].substr(pos+1, param_responses[0].length());
			if (param_name == "Success" && param_value == "true") {
				// init other params
				for(unsigned int i = 1; i < param_responses.size(); i ++) {
					int pos = param_responses[i].find(":");
					std::string param_name = param_responses[i].substr(0, pos);
					std::string param_value = param_responses[i].substr(pos+1, param_responses[i].length());
					if (param_name == "pk") {
						//std::string temp_pk(param_value, 32);
						//pk = temp_pk;
						pk = param_value;
					} else if (param_name == "sk") {
						//std::string temp_sk(param_value, 64);
						//sk = temp_sk;
						sk = param_value;
					} else {
						printf("[Init KeyPair] Invalid param\n");
						return -1;
					}
				}
				return 0;
			} 
			return -1;

		*/
	}
	
}