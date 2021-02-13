#pragma once

#include <string>

enum class NtlmResponseType { v1, v2, v2Session };

std::string make_type1_msg(const std::string& domain, const std::string& host, NtlmResponseType ntlm_resp_type);
std::string make_type3_msg(const std::string& username, const std::string& password, const std::string& domain, const std::string& host, const std::string& msg2_b64_buff, NtlmResponseType ntlm_resp_type);
