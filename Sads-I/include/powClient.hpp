

#ifndef SGXDEDUP_POWCLIENT_HPP
#define SGXDEDUP_POWCLIENT_HPP
#include "configure.hpp"
#include "dataStructure.hpp"
#include "messageQueue.hpp"
#include "protocol.hpp"
#include "sender.hpp"
#include <bits/stdc++.h>

class powClient {
private:
    messageQueue<Data_t>* inputMQ_;
    Sender* senderObj_;
    CryptoPrimitive* cryptoObj_;

    ssl* keySecurityChannel_;
    SSL* sslConnection_;

public:
    powClient(Sender* senderObjTemp);
    ~powClient();

    void run();

    bool insertMQ(Data_t& newChunk);
    bool extractMQ(Data_t& newChunk);
    bool editJobDoneFlag();

    void DecorateFP(BIGNUM* r, uint8_t* fp, uint8_t* outputBuffer);
    void Elimination(BIGNUM* inv, uint8_t* key, uint8_t* output);
};

#endif //SGXDEDUP_POWCLIENT_HPP
