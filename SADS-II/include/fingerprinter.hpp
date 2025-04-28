#ifndef SGXDEDUP_FINGERPRINTER_HPP
#define SGXDEDUP_FINGERPRINTER_HPP

#include "configure.hpp"
#include "cryptoPrimitive.hpp"
#include "dataStructure.hpp"
#include "characterer.hpp"
#include "messageQueue.hpp"

class Fingerprinter {
private:
    messageQueue<Data_t>* inputMQ_;
    Characterer* CharactererObj_;
    CryptoPrimitive* cryptoObj_;

public:
    Fingerprinter(Characterer* CharactererObjTemp);
    ~Fingerprinter();
    void run();
    bool insertMQ(Data_t& newChunk);
    bool extractMQ(Data_t& newChunk);
    bool editJobDoneFlag();
};

#endif //SGXDEDUP_FINGERPRINTER_HPP
