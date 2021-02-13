#pragma once

#include <string>

#define USE_NTLMV1  1
#define USE_NTLM2SESSION   2
#define USE_NTLMV2  3

std::string make_type1_msg(const std::string& domain, const std::string& host, int ntlm_resp_type);
std::string make_type3_msg(const std::string& username, const std::string& password, const std::string& domain, const std::string& host, const std::string& msg2_b64_buff, int ntlm_resp_type);
