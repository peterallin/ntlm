This repo is a fork of hamsergene/ntlm with some changes to user more modern C++ features trying to lessen the amount of
raw pointers and manual memory management. It was made as part of a discussion with a friend and former co-worker about
how we would like this code base to look. If anyone wants to use it for anything, please do so under the same license as
hamstergenes original work.

----------------------


Overview
---------
This is an implementation of ntlm negotiation message using C++.
So, you can use it to pass ntlm authentication in linux platform. (Note: This project can also pass compiling on windows, but I didn't run any test.)
Currently, I don't implement the session security part. But you can still use it to pass ntlm authentication(include ntlmv1, ntlm2session, and ntlmv2).

Usage
---------
There are 2 main functions:
```C++
string make_type1_msg(string domain, string host, int ntlm_resp_type);
string make_type3_msg(string username, string password, string domain, string host, string msg2_b64_buff, int ntlm_resp_type);
```

`ntlm_resp_type` only accepts 3 type values defined in `ntlm.h`
```C++
#define USE_NTLMV1  1
#define USE_NTLM2SESSION   2
#define USE_NTLMV2  3
```

`msg2_b64_buff` is the challenge string you obtain from type2 message.
For example, the `msg2_b64_buff` should be **11223344aabbccdd** in the following type2 message used in a proxy authentication.  

>HTTP/1.1 407 Proxy Authentication Required ( Access is denied.)  
Via: 1.1 VM-2K3R2  
Proxy-Authenticate: Negotiate 11223344aabbccdd  
Connection: Keep-Alive  
Proxy-Connection: Keep-Alive  
Pragma: no-cache  
Cache-Control: no-cache  
Content-Type: text/html  
Content-Length: 0  

You need only include `ntlm.h` in your cpp file.

Compiling
---------
I use [openssl](https://www.openssl.org/) library to implement encryption algorithms used by ntlm. So you need download and compile it on your platform. The library included in this repository is a 64-bit static library built on ubuntu 16.04.

Here is an example:
If you have test.cpp including main() function, you can compile it using the following commands:
```
g++ -g -c util.cpp -o util.o -Iinclude 
g++ -g -c ntlm.cpp -o ntlm.o -Iinclude 
g++ -g -c test.cpp -o test.o -Iinclude 
g++ -o test util.o ntlm.o test.o -Llib -lssl -lcrypto -pthread -ldl
```

License
---------
The MIT License (MIT)

Copyright (c) 2017 dyduyu

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
