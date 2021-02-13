#pragma once

#include <string>

#define USE_NTLMV1  1
#define USE_NTLM2SESSION   2
#define USE_NTLMV2  3

std::string make_type1_msg(std::string domain, std::string host, int ntlm_resp_type);
std::string make_type3_msg(std::string username, std::string password, std::string domain, std::string host, std::string msg2_b64_buff, int ntlm_resp_type);
