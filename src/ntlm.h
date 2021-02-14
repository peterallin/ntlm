#pragma once

// References
//  [1][MS-NLMP]
//  [2][http://davenport.sourceforge.net/ntlm.html]

#include <array>
#include <cstdint>
#include <string>
#include <vector>

// The negotiate message
struct Type1Message
{
    char        signature[8];
    uint32_t    type;
    uint32_t    flag;

    // optional
    // domain security buffer
    uint16_t    dom_len;
    uint16_t    dom_max_len;
    uint32_t    dom_off;

    // optional
    // host security buffer
    uint16_t    hst_len;
    uint16_t    hst_max_len;
    uint32_t    hst_off;

    // optional
    uint8_t        version[8];
};

// The challenge message
struct Type2Message
{
    char        signature[8];
    uint32_t    type;

    // target name security buffer
    uint16_t    target_name_len;
    uint16_t    target_name_max_len;
    uint32_t    target_name_off;

    uint32_t    flag;
    uint8_t        challenge[8];

    // There is a description difference between [1] and [2]
    // In [1], this is an 8-uint8_t array whose elements MUST be zero when sent and MUST be ignored on receipt.
    // But in [2], seems it could be used when Negotiate Local Call is set.
    // Currently, I don't use it.
    uint8_t        reserved[8];

    // optional
    // target info security buffer
    uint16_t    target_info_len;
    uint16_t    target_info_max_len;
    uint32_t    target_info_off;

    // optional
    uint8_t        version[8];
};

// The response message
struct Type3Message
{
    char        signature[8];
    uint32_t    type;

    // LM/LMv2 response security buffer
    uint16_t    lm_challenge_resp_len;
    uint16_t    lm_challenge_resp_max_len;
    uint32_t    lm_challenge_resp_off;

    // NTLM/NTLMv2 response security buffer
    uint16_t    nt_challenge_resp_len;
    uint16_t    nt_challenge_resp_max_len;
    uint32_t    nt_challenge_resp_off;

    // domain security buffer unicode or ascii
    uint16_t    dom_len;
    uint16_t    dom_max_len;
    uint32_t    dom_off;

    // user name security buffer unicode or ascii
    uint16_t    usr_name_len;
    uint16_t    usr_name_max_len;
    uint32_t    usr_name_off;

    // host security buffer unicode or ascii
    uint16_t    hst_len;
    uint16_t    hst_max_len;
    uint32_t    hst_off;

    // optional
    // session key security buffer
    uint16_t    session_key_len;
    uint16_t    session_key_max_len;
    uint32_t    session_key_off;

    // optional
    uint32_t    flag;

    // optional
    uint8_t        version[8];
};

class Message2Handle
{
public:
    explicit Message2Handle(const std::string & msg2_b64_buff);

    const uint8_t* get_challenge();
    bool support_unicode() const;
    const uint8_t* get_target_info(uint16_t& target_info_len);
private:
    Type2Message msg2{};
    std::vector<uint8_t> msg2_buff;

};
constexpr size_t MSG1_SIZE = sizeof(Type1Message);
constexpr size_t MSG2_SIZE = sizeof(Type2Message);
constexpr size_t MSG3_SIZE = sizeof(Type3Message);

#define NTLMSSP_SIGNATURE "NTLMSSP"
constexpr uint32_t TYPE1_INDICATOR = 0x1;
constexpr uint32_t TYPE3_INDICATOR = 0x3;


// ntlmv1 flag
// Negotiate Unicode                (0x00000001)
// Negotiate OEM                    (0x00000002)
// Request Target                   (0x00000004)
// Negotiate NTLM                   (0x00000200)
// Negotiate Always Sign            (0x00008000) <- must set mentioned in [1]
constexpr uint32_t NTLMV1_FLAG = 0x8207;

//Negotiate Extended Security       (0x00080000)
constexpr uint32_t NTLM2SESSION_FLAG = 0x88207;

//Negotiate Target Info             (0x00800000) <-- this is sent by type2 msg indicates support v2
//we still key the flag same as session
constexpr uint32_t NTLMV2_FLAG = 0x88207;

//internal use
std::array<uint8_t,24> calc_lmv1_resp(const std::string& password, const uint8_t* challenge);
std::vector<uint8_t> calc_ntlmv1_resp(const std::string& password, const uint8_t* challenge);
std::tuple<std::array<uint8_t, 24>, std::vector<uint8_t>> calc_ntlm2session_resp(const std::string& password, const uint8_t* challenge, uint8_t* client_nonce);
std::array<uint8_t, 24> calc_lmv2_resp(const std::string& username, const std::string& password, const std::string& domain, const uint8_t* challenge);
std::vector<uint8_t> calc_ntlmv2_resp(const std::string& username, const std::string& password, const std::string& domain, const uint8_t* challenge, const uint8_t* target_info, uint16_t target_info_len);
std::array<uint8_t, MD4_DIGEST_LENGTH> calc_ntlmv1_hash(const std::string& password);
std::array<uint8_t, 8> calc_ntlm2session_hash(uint8_t* session_nonce);
std::array<uint8_t, 16> calc_ntlmv2_hash(const std::string& username, const std::string& password, const std::string& domain);
void create_client_nonce(uint8_t* nonce, size_t len);
void create_blob(const uint8_t* target_info, uint16_t target_info_len, uint8_t* blob, size_t blob_len);
void setup_security_buffer(uint16_t &temp_len,uint32_t &temp_off, uint16_t &msg_len, uint16_t &msg_max_len, uint32_t &msg_off, uint16_t len_val, uint32_t off_val);

