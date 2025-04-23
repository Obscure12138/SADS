#ifndef SGXDEDUP_KEYCLIENT_HPP
#define SGXDEDUP_KEYCLIENT_HPP

#include "configure.hpp"
#include "powClient.hpp"
#include "cryptoPrimitive.hpp"
#include "dataStructure.hpp"
#include "messageQueue.hpp"
#include "ssl.hpp"
#include "../src/pbcwrapper/PBC.h"

class KeyClient {
private:
    messageQueue<Data_t>* inputMQ_;
    powClient* powObj_;
    CryptoPrimitive* cryptoObj_;
    int keyBatchSize_;
    ssl* keySecurityChannel_;
    SSL* sslConnection_;
    uint64_t keyGenNumber_;
    int clientID_;
    std::mutex mutexkeyGenerateSimulatorEncTime_;
    std::mutex mutexkeyGenerateSimulatorStart_;
    vector<timeval> keyGenSimulatorStartTimeCounter_;
    vector<timeval> keyGenSimulatorEndTimeCounter_;
    int totalSimulatorThreadNumber_;
    int currentInitThreadNumber_;
    int batchNumber_;

    BIGNUM* keyN_;
    BIGNUM* fai_N;
    BIGNUM* g;
    BN_CTX* bnCTX;
    

public:
    double keyExchangeEncTime = 0;
    KeyClient(powClient* powObjTemp);
    KeyClient(uint64_t keyGenNumber);
    ~KeyClient();
    //bool outputKeyGenSimulatorRunningTime();
    void run();
    void runKeyGenSimulator();
    bool insertMQ(Data_t& newChunk);
    bool extractMQ(Data_t& newChunk);
    bool editJobDoneFlag();
    bool keyExchange(u_char* batchHashList, int batchNumber, u_char* batchKeyList, int& batchkeyNumber);
    //bool keyExchange(u_char* batchHashList, int batchNumber, u_char* batchKeyList, int& batchkeyNumber, ssl* securityChannel, SSL* sslConnection);
    //bool keyExchange(u_char* batchHashList, int batchNumber, u_char* batchKeyList, int& batchkeyNumber, ssl* securityChannel, SSL* sslConnection, CryptoPrimitive* cryptoObj);

    // void DecorateFP(Zr r, uint8_t* fp, uint8_t* outputBuffer);
    // void Elimination(Zr inv, uint8_t* key, uint8_t* outputBuffer);
    // bool Verify(uint8_t* fp, uint8_t* sf, uint8_t* key);

    void DecorateFP(BIGNUM* r, uint8_t* fp, uint8_t* outputBuffer);
    void Elimination(BIGNUM* inv, uint8_t* key, uint8_t* outputBuffer);
    
#if KEY_GEN_METHOD_TYPE == KEY_GEN_SGX_CTR
    double keyExchangeMaskGenerateTime = 0;
    u_char nonce_[CRYPTO_BLOCK_SZIE - sizeof(uint32_t)];
    uint32_t counter_ = 0;
    bool initClientCTRInfo();
    bool saveClientCTRInfo();
    bool keyExchangeXOR(u_char* result, u_char* input, u_char* xorBase, int batchNumber);
    bool keyExchange(u_char* batchHashList, int batchNumber, u_char* batchKeyList, int& batchkeyNumber, NetworkHeadStruct_t netHead);
    bool keyExchange(u_char* batchHashList, int batchNumber, u_char* batchKeyList, int& batchkeyNumber, ssl* securityChannel, SSL* sslConnection, CryptoPrimitive* cryptoObj, u_char* nonce, uint32_t counter, NetworkHeadStruct_t netHead);
#endif
};

#endif //SGXDEDUP_KEYCLIENT_HPP
