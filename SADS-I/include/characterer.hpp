#ifndef SGXDEDUP__CHARACTERER_HPP
#define SGXDEDUP__CHARACTERER_HPP

#include "configure.hpp"
#include "cryptoPrimitive.hpp"
#include "dataStructure.hpp"
#include "messageQueue.hpp"
#include "keyClient.hpp"

class Characterer {
private :
    CryptoPrimitive* cryptoObj_;
    KeyClient* keyClientObj_;
    messageQueue<Data_t>* inputMQ_;

    int slidingWinSize_;
    uint64_t polyBase_;
    uint64_t polyMOD_;
    uint64_t* powerLUT_;
    uint64_t* removeLUT_;

public :
    Characterer(KeyClient* keyClientObjTemp);
    ~Characterer();
    void MinhashRun();
    void SimilarityHashRun();
    void ParseRun();
    bool insertMQ(Data_t& newChunk);
    bool extractMQ(Data_t& newChunk);
    bool insertParseMQ(Data_t& newChunk);
    bool extractParseMQ(Data_t& newChunk);
    bool editJobDoneFlag();
    bool editParseMQJobDoneFlag();
};

#endif
