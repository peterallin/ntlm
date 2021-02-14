#ifndef	__NTLM_UTIL_INCLUDE
#define	__NTLM_UTIL_INCLUDE

#include <array>
#include <cstring>
#include <iterator>
#include <string>
#include <vector>
#include <openssl/des.h>
#include <openssl/md4.h>
#include <openssl/md5.h>
#include <openssl/hmac.h>
#include <openssl/buffer.h>

#define BASE64_ENCODE_LENGTH(len)	(4 * (((len) + 2) / 3))
#define BASE64_DECODE_LENGTH(len)	(3 * (((len) + 3) / 4))

std::string to_uppercase(const std::string& s);

bool is_big_endian();
uint16_t to_little_endian(uint16_t i_data);
uint32_t to_little_endian(uint32_t i_data);
uint64_t to_little_endian(uint64_t i_data);

void des_enc(uint8_t* key, DES_cblock* data, DES_cblock* result);
void md4_enc(uint8_t* data, size_t data_len, uint8_t* result);
void md5_enc(uint8_t* data, size_t data_len, uint8_t* result);
void hmac_md5_enc(void* key, int key_len, const uint8_t* data, int data_len, uint8_t* digest, unsigned int digest_len);

std::string ascii_to_unicode(const std::string& ascii);
uint64_t create_timestamp();

template<size_t I, size_t J>
std::array<uint8_t, I+J> concat(const std::array<uint8_t, I>& a, const std::array<uint8_t, J>& b)
{
    std::array<uint8_t, I+J> result{};
    std::copy(a.begin(), a.end(), &result[0]);
    std::copy(b.begin(), b.end(), &result[I]);
    return result;
}

template<typename A, typename B>
std::vector<uint8_t> concat(const A& a, const B& b)
{
    std::vector<uint8_t> result;
    std::copy(a.begin(), a.end(), std::back_inserter(result));
    std::copy(b.begin(), b.end(), std::back_inserter(result));
    return result;
}


void base64_encode(const std::vector<char>& src, std::back_insert_iterator<std::vector<char>> dst);
size_t base64_decode(const char *src, uint8_t *dst);

#endif
