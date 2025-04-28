#ifndef SGXDEDUP_KEYSERVER_HPP
#define SGXDEDUP_KEYSERVER_HPP

#include "configure.hpp"
#include "dataStructure.hpp"
#include "messageQueue.hpp"
#include "openssl/bn.h"
#include "openssl/crypto.h"
#include "ssl.hpp"
#include <bits/stdc++.h>

#define SERVERSIDE 0
#define CLIENTSIDE 1
#define KEYMANGER_PRIVATE_KEY "key/sslKeys/server-key.pem"

struct limitInfo{
    int threshold;
    int lastUserID;
    bool limit;
    bool multiuser;
    int currentEpochCount;
    vector<double> historyCount;
    int delay;
    int maxDelay;
    set<string> fpSet;
};

class keyServer {
private:
    BIGNUM* keyN_;
    BIGNUM* sk;
    BN_CTX* bnCTX;
    
    std::mutex multiThreadMutex_;
    std::mutex multiThreadCountMutex_;
    std::mutex clientThreadNumberCountMutex_;
    uint64_t keyGenerateCount_;
    uint64_t clientThreadCount_;
    std::mutex mutexSessionKeyUpdate;
#if KEY_GEN_METHOD_TYPE == KEY_GEN_SGX_CTR
    bool offlineGenerateFlag_ = false;
#endif
    ssl* keySecurityChannel_;
    map<string, limitInfo> SFList;
public:
    keyServer(ssl* keySecurityChannelTemp);
    ~keyServer();
#if KEY_GEN_METHOD_TYPE == KEY_GEN_SGX_CTR
    void runCTRModeMaskGenerate();
#endif
    void runKeyGenerateThread(SSL* connection);
    void updateEpoch();
};

#endif //SGXDEDUP_KEYSERVER_HPP
