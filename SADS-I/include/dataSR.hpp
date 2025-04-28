#ifndef SGXDEDUP_DATASR_HPP
#define SGXDEDUP_DATASR_HPP

#include "boost/bind.hpp"
#include "boost/thread.hpp"
#include "configure.hpp"
#include "dataStructure.hpp"
#include "dedupCore.hpp"
#include "messageQueue.hpp"
#include "cryptoPrimitive.hpp"
#include "protocol.hpp"
#include "ssl.hpp"
#include "storageCore.hpp"
#include <bits/stdc++.h>

using namespace std;

extern Configure config;

class DataSR {
private:
    StorageCore* storageObj_;
    CryptoPrimitive* cryptoObj_;
    DedupCore* dedupCoreObj_;
    uint32_t restoreChunkBatchNumber_;
    ssl* powSecurityChannel_;
    ssl* dataSecurityChannel_;
#if MULTI_CLIENT_UPLOAD_TEST == 1
    std::mutex mutexSessions_;
    std::mutex mutexCrypto_;
    std::mutex mutexRestore_;
#endif
public:
    DataSR(StorageCore* storageObj, DedupCore* dedupCoreObj, ssl* powSecurityChannelTemp, ssl* dataSecurityChannelTemp);
    ~DataSR() {};
    void runData(SSL* sslConnection);
    void runPow(SSL* sslConnection);
};

#endif //SGXDEDUP_DATASR_HPP
