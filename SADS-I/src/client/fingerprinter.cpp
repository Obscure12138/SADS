#include "fingerprinter.hpp"
#include "openssl/rsa.h"
#include <sys/time.h>

extern Configure config;

struct timeval timestartFingerprinter;
struct timeval timeendFingerprinter;

void PRINT_BYTE_ARRAY_FINGERPRINTER(
    FILE* file, void* mem, uint32_t len)
{
    if (!mem || !len) {
        fprintf(file, "\n( null )\n");
        return;
    }
    uint8_t* array = (uint8_t*)mem;
    fprintf(file, "%u bytes:\n{\n", len);
    uint32_t i = 0;
    for (i = 0; i < len - 1; i++) {
        fprintf(file, "0x%x, ", array[i]);
        if (i % 8 == 7)
            fprintf(file, "\n");
    }
    fprintf(file, "0x%x ", array[i]);
    fprintf(file, "\n}\n");
}

Fingerprinter::Fingerprinter(Characterer* charactererObjTemp)
{
    inputMQ_ = new messageQueue<Data_t>;
    charactererObj_ = charactererObjTemp;
    cryptoObj_ = new CryptoPrimitive();
}

Fingerprinter::~Fingerprinter()
{
    delete cryptoObj_;
    inputMQ_->~messageQueue();
    delete inputMQ_;
}

void Fingerprinter::run()
{

#if SYSTEM_BREAK_DOWN == 1
#endif
    double generatePlainChunkHashTime = 0;
    long diff;
    double second;
    bool JobDoneFlag = false;
    while (true) {
        Data_t tempChunk;
        if (inputMQ_->done_ && inputMQ_->isEmpty()) {
            JobDoneFlag = true;
        }
        if (extractMQ(tempChunk)) {
            if (tempChunk.dataType == DATA_TYPE_RECIPE) {
                charactererObj_->insertMQ(tempChunk);
                continue;
            } else {

#if SYSTEM_BREAK_DOWN == 1
#endif
                gettimeofday(&timestartFingerprinter, NULL);
                bool generatePlainChunkHashStatus = cryptoObj_->generateHash(tempChunk.chunk.logicData, tempChunk.chunk.logicDataSize, tempChunk.chunk.chunkHash);
                gettimeofday(&timeendFingerprinter, NULL);
                diff = 1000000 * (timeendFingerprinter.tv_sec - timestartFingerprinter.tv_sec) + timeendFingerprinter.tv_usec - timestartFingerprinter.tv_usec;
                second = diff / 1000000.0;
                generatePlainChunkHashTime += second;
#if SYSTEM_BREAK_DOWN == 1
#endif
                if (generatePlainChunkHashStatus) {
                    charactererObj_->insertMQ(tempChunk);
                } else {
                    cerr << "Fingerprinter : generate cipher chunk hash error, exiting" << endl;
                    return;
                }
            }
        }
        if (JobDoneFlag) {
            if (!charactererObj_->editJobDoneFlag()) {
                cerr << "Fingerprinter : error to set job done flag for encoder" << endl;
            }
            break;
        }
    }
#if SYSTEM_BREAK_DOWN == 1
#endif
    cout << "Fingerprinter : cipher chunk crypto hash generate work time = " << generatePlainChunkHashTime << " s" << endl;
    return;
}

bool Fingerprinter::insertMQ(Data_t& newChunk)
{
    return inputMQ_->push(newChunk);
}

bool Fingerprinter::extractMQ(Data_t& newChunk)
{
    return inputMQ_->pop(newChunk);
}

bool Fingerprinter::editJobDoneFlag()
{
    inputMQ_->done_ = true;
    if (inputMQ_->done_) {
        return true;
    } else {
        return false;
    }
}
