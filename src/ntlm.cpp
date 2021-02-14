#include <ntlm/ntlm.h>
#include "util.h"
#include <openssl/rand.h>
#include <array>
#include <cstring>
#include <tuple>
#include "ntlm.h"


#if defined(USE_HACKS_FOR_REPEATABLE_TESTS)
int not_so_random_bytes(unsigned char *buf, unsigned long num){
    memset(buf, 42, num);
    return 1;
}

#define RAND_bytes(buf, len) not_so_random_bytes(buf, len)

uint64_t create_not_so_timestamp()
{
    return 0xdeadbeefbeefdead;
}

#define create_timestamp create_not_so_timestamp
#endif

std::string make_type1_msg(const std::string& domain, const std::string& host, NtlmResponseType ntlm_resp_type)
{
    std::string upper_domain = to_uppercase(domain);
    std::string upper_host = to_uppercase(host);
    size_t dom_len = upper_domain.length();
    size_t hst_len = upper_host.length();    
    
    Type1Message msg1{};

    strcpy(msg1.signature, NTLMSSP_SIGNATURE);
    
    msg1.type = to_little_endian(TYPE1_INDICATOR);
    
    if( NtlmResponseType::v1 == ntlm_resp_type)
        msg1.flag = to_little_endian(NTLMV1_FLAG);
    else if( NtlmResponseType::v2Session == ntlm_resp_type)
        msg1.flag = to_little_endian(NTLM2SESSION_FLAG);
    else if (NtlmResponseType::v2 == ntlm_resp_type)
        msg1.flag = to_little_endian(NTLMV2_FLAG);
    else
        return "";
        
        
    msg1.dom_len = msg1.dom_max_len =to_little_endian((uint16_t) dom_len);
    msg1.dom_off = to_little_endian((uint32_t) MSG1_SIZE);
    
    msg1.hst_len = msg1.hst_max_len = to_little_endian((uint16_t) hst_len);
    msg1.hst_off  = to_little_endian((uint32_t)(MSG1_SIZE + dom_len));
    
    size_t buff_size = MSG1_SIZE + dom_len + hst_len;
    std::vector<char> buff(buff_size);
    memmove(buff.data(), &msg1, MSG1_SIZE);
    if(0 != dom_len)
    	memmove(buff.data() + MSG1_SIZE, upper_domain.c_str(), dom_len);
    if(0 != hst_len)
	    memmove(buff.data() + MSG1_SIZE + dom_len, upper_host.c_str(), hst_len);

    
    size_t base64_len = BASE64_ENCODE_LENGTH(buff_size) + 1;
    std::vector<char> buff_base64(base64_len);
    base64_encode(buff.data(), buff_base64.data(), buff_size);
    buff_base64[base64_len - 1] = '\0';
    std::string result(buff_base64.data());
    
	return result;
}

std::string make_type3_msg(std::string username, const std::string& password, std::string domain, std::string host, const std::string& msg2_b64_buff, NtlmResponseType ntlm_resp_type)
{
    if(0 == msg2_b64_buff.length())
    {
        return "";
    }
    Message2Handle msg2_handle(msg2_b64_buff);
    
    bool support_unicode = msg2_handle.support_unicode();
    
    Type3Message msg3{};
    uint16_t lm_challenge_resp_len, nt_challenge_resp_len, dom_len, usr_name_len, hst_len;
    uint32_t lm_challenge_resp_off, nt_challenge_resp_off, dom_off, usr_name_off, hst_off;
        
    strcpy(msg3.signature, NTLMSSP_SIGNATURE);
    msg3.type = to_little_endian(TYPE3_INDICATOR);

    std::array<uint8_t, 24> lm_resp{};
    std::vector<uint8_t> ntlm_resp(24);
    setup_security_buffer(lm_challenge_resp_len, lm_challenge_resp_off, msg3.lm_challenge_resp_len, msg3.lm_challenge_resp_max_len, msg3.lm_challenge_resp_off,
            24, 
            MSG3_SIZE);
        
    setup_security_buffer(dom_len, dom_off, msg3.dom_len, msg3.dom_max_len, msg3.dom_off, 
        support_unicode ? 2*(uint16_t) domain.length() : (uint16_t) domain.length(), 
        lm_challenge_resp_off + lm_challenge_resp_len);
    
    setup_security_buffer(usr_name_len, usr_name_off, msg3.usr_name_len, msg3.usr_name_max_len, msg3.usr_name_off, 
        support_unicode ? 2*(uint16_t) username.length() : (uint16_t) username.length(), 
        dom_off + dom_len);
    
    setup_security_buffer(hst_len, hst_off, msg3.hst_len, msg3.hst_max_len, msg3.hst_off, 
        support_unicode ? 2*(uint16_t) host.length() : (uint16_t) host.length(), 
        usr_name_off + usr_name_len);
        
    setup_security_buffer(nt_challenge_resp_len, nt_challenge_resp_off, msg3.nt_challenge_resp_len, msg3.nt_challenge_resp_max_len, msg3.nt_challenge_resp_off, 
            24, 
            hst_off + hst_len);

    msg3.session_key_len = msg3.session_key_max_len = 0;

    if( NtlmResponseType::v1 == ntlm_resp_type)
    {
        msg3.flag = to_little_endian(NTLMV1_FLAG);

        lm_resp = calc_lmv1_resp(password, msg2_handle.get_challenge());
        ntlm_resp = calc_ntlmv1_resp(password, msg2_handle.get_challenge());
        
    }else if( NtlmResponseType::v2Session == ntlm_resp_type)
    {
        msg3.flag = to_little_endian(NTLM2SESSION_FLAG);
        
        uint8_t client_nonce[8];
        memset(client_nonce, 0, 8);
        create_client_nonce(client_nonce, 8);
        std::tie(lm_resp, ntlm_resp) = calc_ntlm2session_resp(password, msg2_handle.get_challenge(), client_nonce);
        
    }else if( NtlmResponseType::v2 == ntlm_resp_type)
    {
        msg3.flag = to_little_endian(NTLM2SESSION_FLAG);
        lm_resp = calc_lmv2_resp(username, password, domain, msg2_handle.get_challenge());
        
        uint16_t target_info_len = 0;
        const uint8_t* target_info = msg2_handle.get_target_info(target_info_len);
        size_t blob_len = 28 + target_info_len; //the blob fixed len + target_info_len
        size_t ntlmv2_resp_len = 16 + blob_len;// hmac + blob

        setup_security_buffer(nt_challenge_resp_len, nt_challenge_resp_off, msg3.nt_challenge_resp_len, msg3.nt_challenge_resp_max_len, msg3.nt_challenge_resp_off, 
            ntlmv2_resp_len, 
            hst_off + hst_len);
        ntlm_resp =  calc_ntlmv2_resp(username, password, domain, msg2_handle.get_challenge(), target_info, target_info_len);
        
    }else
    {
        return "";
    }
    
    size_t msg3_buff_len = MSG3_SIZE + lm_challenge_resp_len + nt_challenge_resp_len + dom_len + usr_name_len + hst_len;
    std::vector<char> msg3_buff(msg3_buff_len);
    memmove(msg3_buff.data(), &msg3, MSG3_SIZE);
    memmove(msg3_buff.data() + lm_challenge_resp_off, lm_resp.data(), lm_challenge_resp_len);
    memmove(msg3_buff.data() + nt_challenge_resp_off, ntlm_resp.data(), nt_challenge_resp_len);

    if(support_unicode)
    {
        domain = ascii_to_unicode(domain);
        username = ascii_to_unicode(username);
        host = ascii_to_unicode(host);
    }
    memmove(msg3_buff.data() + dom_off, domain.data(), dom_len);
    memmove(msg3_buff.data() + usr_name_off, username.data(), usr_name_len);
    memmove(msg3_buff.data() + hst_off, host.data(), hst_len);

    std::vector<char> msg3_buff_b64(BASE64_ENCODE_LENGTH(msg3_buff_len) + 1);
    base64_encode(msg3_buff.data(), msg3_buff_b64.data(), msg3_buff_len);
    msg3_buff_b64[BASE64_ENCODE_LENGTH(msg3_buff_len)] = '\0';
    std::string result(msg3_buff_b64.data());

    return result;
}

std::array<uint8_t,24> calc_lmv1_resp(const std::string& password, const uint8_t* challenge)
{
    std::string upper_pwd = to_uppercase(password);
    size_t upper_pwd_len = upper_pwd.length();
    uint8_t pwd[14];
    memset(pwd, 0, 14);
    size_t mv_len = upper_pwd_len < 14 ? upper_pwd_len : 14;
    memmove(pwd, upper_pwd.c_str(), mv_len);
    uint8_t* pwd_l = pwd;// low 7 bytes
    uint8_t* pwd_h = pwd + 7;// high 7 bytes
    
    uint8_t lm_hash_padded[21];
    memset(lm_hash_padded, 0, 21);
    
    uint8_t* lm_hash_l = lm_hash_padded;// low 8 bytes
    uint8_t* lm_hash_h = lm_hash_padded + 8; // high 8 bytes
    uint8_t* lm_hash_p = lm_hash_padded + 16; // the padded 5 bytes
    DES_cblock magic = { 0x4B, 0x47, 0x53, 0x21, 0x40, 0x23, 0x24, 0x25 }; //KGS!@$%
    
    //key data result
    des_enc(pwd_l, &magic, (DES_cblock*)lm_hash_l);
    des_enc(pwd_h, &magic, (DES_cblock*)lm_hash_h);
    memset(lm_hash_p, 0, 5);

    std::array<uint8_t,24> result{};
    uint8_t* lm_resp1 = result.data();
    uint8_t* lm_resp2 = result.data() + 8;
    uint8_t* lm_resp3 = result.data() + 16;
    
    uint8_t* lm_hash_padded1 = lm_hash_padded;
    uint8_t* lm_hash_padded2 = lm_hash_padded + 7;
    uint8_t* lm_hash_padded3 = lm_hash_padded + 14;

    des_enc(lm_hash_padded1, (DES_cblock*) challenge, (DES_cblock*) lm_resp1);
    des_enc(lm_hash_padded2, (DES_cblock*) challenge, (DES_cblock*) lm_resp2);
    des_enc(lm_hash_padded3, (DES_cblock*) challenge, (DES_cblock*) lm_resp3);

    return result;
}

std::vector<uint8_t> calc_ntlmv1_resp(const std::string& password, const uint8_t* challenge)
{
    uint8_t ntlmv1_hash_padded[21];
    memset(ntlmv1_hash_padded, 0, 21);

    auto const ntlmv1_hash = calc_ntlmv1_hash(password);
    
    memset(ntlmv1_hash_padded, 0, 21);
    memmove(ntlmv1_hash_padded, ntlmv1_hash.data(), ntlmv1_hash.size());

    std::vector<uint8_t> result(24);
    uint8_t* ntlmv1_resp1 = result.data();
    uint8_t* ntlmv1_resp2 = result.data() + 8;
    uint8_t* ntlmv1_resp3 = result.data() + 16;
    
    uint8_t* ntlmv1_hash_padded1 = ntlmv1_hash_padded;
    uint8_t* ntlmv1_hash_padded2 = ntlmv1_hash_padded  + 7;
    uint8_t* ntlmv1_hash_padded3 = ntlmv1_hash_padded  + 14;
    
    des_enc(ntlmv1_hash_padded1, (DES_cblock*) challenge, (DES_cblock*) ntlmv1_resp1);
    des_enc(ntlmv1_hash_padded2, (DES_cblock*) challenge, (DES_cblock*) ntlmv1_resp2);
    des_enc(ntlmv1_hash_padded3, (DES_cblock*) challenge, (DES_cblock*) ntlmv1_resp3);

    return result;
}

std::tuple<std::array<uint8_t, 24>, std::vector<uint8_t>> calc_ntlm2session_resp(const std::string& password, const uint8_t* challenge, uint8_t* client_nonce)
{
    std::array<uint8_t, 24> lm_resp{};
    memmove(lm_resp.data(), client_nonce, 8);
        
    uint8_t session_nonce[16];
    memset(session_nonce, 0, 16);
    concat(challenge, 8, client_nonce, 8, session_nonce);
    
    auto const ntlm2session_hash = calc_ntlm2session_hash(session_nonce);

    uint8_t ntlmv1_hash_padded[21];
    memset(ntlmv1_hash_padded, 0, 21);

    auto const ntlmv1_hash = calc_ntlmv1_hash(password);
    
    memset(ntlmv1_hash_padded, 0, 21);
    memmove(ntlmv1_hash_padded, ntlmv1_hash.data(), ntlmv1_hash.size());

    std::vector<uint8_t> ntlm2session_resp(24);
    uint8_t* ntlm2session_resp1 = ntlm2session_resp.data();
    uint8_t* ntlm2session_resp2 = ntlm2session_resp.data() + 8;
    uint8_t* ntlm2session_resp3 = ntlm2session_resp.data() + 16;
    
    uint8_t* ntlmv1_hash_padded1 = ntlmv1_hash_padded;
    uint8_t* ntlmv1_hash_padded2 = ntlmv1_hash_padded  + 7;
    uint8_t* ntlmv1_hash_padded3 = ntlmv1_hash_padded  + 14;
    
    des_enc(ntlmv1_hash_padded1, (DES_cblock*) ntlm2session_hash.data(), (DES_cblock*) ntlm2session_resp1);
    des_enc(ntlmv1_hash_padded2, (DES_cblock*) ntlm2session_hash.data(), (DES_cblock*) ntlm2session_resp2);
    des_enc(ntlmv1_hash_padded3, (DES_cblock*) ntlm2session_hash.data(), (DES_cblock*) ntlm2session_resp3);

    return std::make_tuple(lm_resp, ntlm2session_resp);
}

std::array<uint8_t, 24> calc_lmv2_resp(const std::string& username, const std::string& password, const std::string& domain, const uint8_t* challenge)
{
    uint8_t client_nonce[8];
    memset(client_nonce, 0, 8);
    create_client_nonce(client_nonce, 8);

    uint8_t data[16];
    memset(data, 0, 16);
    concat(client_nonce, 8, challenge, 8, data);
    
    uint8_t ntlmv2_hash[16];
    memset(ntlmv2_hash, 0, 16);
    calc_ntlmv2_hash(username, password, domain, ntlmv2_hash);
    
    uint8_t hmac[16];
    memset(hmac, 0, 16);
    hmac_md5_enc((void*)ntlmv2_hash, 16, data, 16, hmac, 16);

    std::array<uint8_t, 24> result{};
    concat(hmac, 16, client_nonce, 8, result.data());
    return result;
}

std::vector<uint8_t> calc_ntlmv2_resp(const std::string& username, const std::string& password, const std::string& domain, const uint8_t* challenge, const uint8_t* target_info, uint16_t const target_info_len)
{
    size_t const blob_len = 28 + target_info_len; //the blob fixed len + target_info_len
    std::vector<uint8_t> blob(blob_len);
    create_blob(target_info, target_info_len, blob.data(), blob_len);
    
    size_t challenge_len = 8;
    size_t data_len = challenge_len + blob_len;
    std::vector<uint8_t> data(data_len);
    concat(challenge, challenge_len, blob.data(), blob_len, data.data());

    uint8_t ntlmv2_hash[16];
    memset(ntlmv2_hash, 0, 16);
    calc_ntlmv2_hash(username, password, domain, ntlmv2_hash);

    uint8_t hmac[16];
    memset(hmac, 0, 16);
    hmac_md5_enc((void*)ntlmv2_hash, 16, data.data(), data_len, hmac, 16);

    std::vector<uint8_t> result(blob_len + sizeof(hmac));
    concat(hmac, 16, blob.data(), blob_len, result.data());
    return result;
}

std::array<uint8_t, MD4_DIGEST_LENGTH> calc_ntlmv1_hash(const std::string& password)
{
    std::array<uint8_t, MD4_DIGEST_LENGTH> result{};
    std::string unicode_pwd = ascii_to_unicode(password);
    md4_enc((uint8_t*)unicode_pwd.c_str(), unicode_pwd.length() , result.data());
    return result;
}

//16-uint8_t session_nonce
//8-uint8_t session_hash
std::array<uint8_t, 8> calc_ntlm2session_hash(uint8_t* session_nonce)
{
    //session_nonce is 16-uint8_t
    //session_hash is 8 uint8_t
    std::array<uint8_t, 8> result{};
    uint8_t md5_nonce[16];
    md5_enc(session_nonce, 16, md5_nonce);
    memmove(result.data(), md5_nonce, 8);
    return  result;
}

void calc_ntlmv2_hash(const std::string& username, const std::string& password, const std::string& domain, uint8_t* ntlmv2_hash)
{
    memset(ntlmv2_hash, 0, 16);

    auto const ntlmv1_hash = calc_ntlmv1_hash(password);

    std::string const unicode_name_dom = ascii_to_unicode(to_uppercase(username)) + ascii_to_unicode(domain);
    hmac_md5_enc((void*)ntlmv1_hash.data(), ntlmv1_hash.size(), (uint8_t*)unicode_name_dom.c_str(), unicode_name_dom.length(), ntlmv2_hash, 16);
}

void create_client_nonce(uint8_t* nonce, size_t len)
{
    memset(nonce, 0, len);
    if(8 != len)
    {
        return;
    }
	int ret = RAND_bytes(nonce, 8);
	//if fail, set 0xffffffff0102034
	if(ret != 1)
	{
        for(int i = 0; i < 4; ++i)
        {
        	nonce[i] = 0xff;
        }
        
        for(int j = 4; j < 8; ++j)
		{
			nonce[j] = j;
		}

	}
}

void create_blob(const uint8_t* target_info, uint16_t target_info_len, uint8_t* blob, size_t blob_len)
{
   /*
    * Description   Content
    * 0             Blob Signature      0x01010000
    * 4             Reserved            long (0x00000000)
    * 8             Timestamp           Little-endian, 64-bit signed value representing the number of tenths of a microsecond since January 1, 1601.
    * 16            Client Nonce        8 bytes
    * 24            Unknown             4 bytes
    * 28            Target Information  Target Information block (from the Type 2 message).
    * (variable)    Unknown             4 bytes
    */
    memset(blob, 0, blob_len);
    if (28 + target_info_len != blob_len)
    {
        return;
    }

    uint64_t timestamp = create_timestamp();
    uint8_t client_nonce[8];
    memset(client_nonce, 0, 8);
    create_client_nonce(client_nonce, 8);
    
    //uint8_t *blob = new uint8_t[blob_len];
    memset(blob, 0, blob_len);
    blob[0] = 0x1;
    blob[1] = 0x1;
    memmove(blob + 8, &timestamp, 8);
    memmove(blob + 16, client_nonce, 8);
    memmove(blob + 28, target_info, target_info_len);
}

void setup_security_buffer(uint16_t &temp_len,uint32_t &temp_off, uint16_t &msg_len, uint16_t &msg_max_len, uint32_t &msg_off, uint16_t len_val, uint32_t off_val)
{
    temp_len = len_val;
    temp_off = off_val;
    msg_len = msg_max_len = to_little_endian(len_val);
    msg_off = to_little_endian(off_val);
}


Message2Handle::Message2Handle(const std::string & msg2_b64_buff)
{
    memset(&msg2, 0, MSG2_SIZE);
    size_t msg2_buff_len = BASE64_DECODE_LENGTH(msg2_b64_buff.length());
    msg2_buff.resize(msg2_buff_len);
    base64_decode(msg2_b64_buff.c_str(), msg2_buff.data());
    memmove(&msg2, msg2_buff.data(), MSG2_SIZE);
    /*
    * following is a tricky part
    * the memmove directly may cause:
    * some little endian data was recognized as big endian data in big endian machine
    * so,just call toLittleEndian() in TmAuDIUtil could solve
    */
    if(is_big_endian())
    {
        msg2.type = to_little_endian(msg2.type);
        msg2.target_name_len = to_little_endian(msg2.target_name_len);
        msg2.target_name_max_len = to_little_endian(msg2.target_name_max_len);
        msg2.target_name_off = to_little_endian(msg2.target_name_off);
        msg2.flag = to_little_endian(msg2.flag);
        msg2.target_info_len = to_little_endian(msg2.target_info_len);
        msg2.target_info_max_len = to_little_endian(msg2.target_info_max_len);
        msg2.target_info_off = to_little_endian(msg2.target_info_off);
    }
    
}

const uint8_t* Message2Handle::get_challenge()
{
    return msg2.challenge;
}

bool Message2Handle::support_unicode() const
{
    return msg2.flag & 0x1;
}

const uint8_t* Message2Handle::get_target_info(uint16_t& target_info_len)
{
    target_info_len = msg2.target_info_len;
  
    const auto* target_info = (const uint8_t*)( msg2_buff.data() + msg2.target_info_off);
    return target_info;
}