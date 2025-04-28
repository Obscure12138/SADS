#include "powClient.hpp"
#include <sys/time.h>

using namespace std;

extern Configure config;

struct timeval timestartPowClient;
struct timeval timeendPowClient;

void print(const char* mem, uint32_t len, uint32_t type)
{
    if (type == 1) {
        cout << mem << endl;
    } else if (type == 3) {
        uint32_t number;
        memcpy(&number, mem, sizeof(uint32_t));
        cout << number << endl;
    } else if (type == 2) {
        if (!mem || !len) {
            fprintf(stderr, "\n( null )\n");
            return;
        }
        uint8_t* array = (uint8_t*)mem;
        fprintf(stderr, "%u bytes:\n{\n", len);
        uint32_t i = 0;
        for (i = 0; i < len - 1; i++) {
            fprintf(stderr, "0x%x, ", array[i]);
            if (i % 8 == 7)
                fprintf(stderr, "\n");
        }
        fprintf(stderr, "0x%x ", array[i]);
        fprintf(stderr, "\n}\n");
    }
}

void PRINT_BYTE_ARRAY_POW_CLIENT(FILE* file, void* mem, uint32_t len)
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

void powClient::run()
{
#if SYSTEM_BREAK_DOWN == 1
    double powEnclaveCaluationTime = 0;
    double powExchangeInofrmationTime = 0;
    double powBuildHashListTime = 0;
    long diff;
    double second;
#endif
    vector<Data_t> batchChunk;
    uint64_t powBatchSize = config.getPOWBatchSize();
    u_char* batchChunkLogicDataCharBuffer;
    batchChunkLogicDataCharBuffer = (u_char*)malloc(sizeof(u_char) * (MAX_CHUNK_SIZE + sizeof(int)) * powBatchSize);
    memset(batchChunkLogicDataCharBuffer, 0, sizeof(u_char) * (MAX_CHUNK_SIZE + sizeof(int)) * powBatchSize);
    Data_t tempChunk;
    int netstatus;
    int currentBatchChunkNumber = 0;
    bool jobDoneFlag = false;
    uint32_t currentBatchSize = 0;
    batchChunk.clear();

    while (true) {

        if (inputMQ_->done_ && inputMQ_->isEmpty()) {
            jobDoneFlag = true;
        }
        if (extractMQ(tempChunk)) {
            if (tempChunk.dataType == DATA_TYPE_RECIPE) {
                senderObj_->insertMQ(tempChunk);
                continue;
            } else {
                cryptoObj_->encryptWithKey(tempChunk.chunk.logicData,tempChunk.chunk.logicDataSize,tempChunk.chunk.encryptKey,tempChunk.chunk.logicData);
                cryptoObj_->generateHash(tempChunk.chunk.logicData,tempChunk.chunk.logicDataSize,tempChunk.chunk.chunkHash);
                tempChunk.chunk.type = CHUNK_TYPE_NEED_UPLOAD;
                senderObj_->insertMQ(tempChunk);
            }
        }
        if (jobDoneFlag) {
            break;
        }
    }
    if (!senderObj_->editJobDoneFlag()) {
        cerr << "PowClient : error to set job done flag for sender" << endl;
    }
#if SYSTEM_BREAK_DOWN == 1
    cout << "PowClient : enclave compute work time = " << powEnclaveCaluationTime << " s" << endl;
    cout << "PowClient : build hash list and insert hash to chunk time = " << powBuildHashListTime << " s" << endl;
    cout << "PowClient : exchange status to storage service provider time = " << powExchangeInofrmationTime << " s" << endl;
    cout << "PowClient : Total work time = " << powExchangeInofrmationTime + powEnclaveCaluationTime + powBuildHashListTime << " s" << endl;
#endif
    free(batchChunkLogicDataCharBuffer);
    return;
}


powClient::powClient(Sender* senderObjTemp)
{
    inputMQ_ = new messageQueue<Data_t>;
    senderObj_ = senderObjTemp;
    cryptoObj_ = new CryptoPrimitive();
#if SYSTEM_BREAK_DOWN == 1
    struct timeval timestartEnclave;
    struct timeval timeendEnclave;
    long diff;
    double second;
#endif
#if SYSTEM_BREAK_DOWN == 1
    gettimeofday(&timestartEnclave, NULL);
#endif
    bool loginToServerStatus = senderObj_->sendLogInMessage(CLIENT_SET_LOGIN);
#if SYSTEM_BREAK_DOWN == 1
    gettimeofday(&timeendEnclave, NULL);
    diff = 1000000 * (timeendEnclave.tv_sec - timestartEnclave.tv_sec) + timeendEnclave.tv_usec - timestartEnclave.tv_usec;
    second = diff / 1000000.0;
    cout << "PowClient : sealed init login ot storage server work time = " << second << " s" << endl;
#endif
    if (loginToServerStatus) {
        cerr << "PowClient : login to storage service provider success" << endl;
    } else {
        cerr << "PowClient : login to storage service provider error" << endl;
    }
}

powClient::~powClient()
{
    inputMQ_->~messageQueue();
    delete inputMQ_;
    delete cryptoObj_;
}

bool powClient::editJobDoneFlag()
{
    inputMQ_->done_ = true;
    if (inputMQ_->done_) {
        return true;
    } else {
        return false;
    }
}

bool powClient::insertMQ(Data_t& newChunk)
{
    return inputMQ_->push(newChunk);
}

bool powClient::extractMQ(Data_t& newChunk)
{
    return inputMQ_->pop(newChunk);
}


