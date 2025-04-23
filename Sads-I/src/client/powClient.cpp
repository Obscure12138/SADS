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

    double encryptTime = 0;
    double dupDetectionTime = 0;
    long diff;
    double second;
    struct timeval timestart;
    struct timeval timeend;

    vector<Data_t> batchChunk;
    uint64_t powBatchSize = config.getPOWBatchSize();
    u_char chunkHashList[powBatchSize* CHUNK_HASH_SIZE];
    Data_t tempChunk;
    int netstatus;
    int currentBatchChunkNumber = 0;
    bool jobDoneFlag = false;
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
                gettimeofday(&timestart,NULL);

                cryptoObj_->encryptWithKey(tempChunk.chunk.logicData, tempChunk.chunk.logicDataSize, tempChunk.chunk.encryptKey,tempChunk.chunk.logicData);
                
                gettimeofday(&timeend,NULL);
                diff = 1000000 * (timeend.tv_sec - timestart.tv_sec) + timeend.tv_usec - timestart.tv_usec;
                second = diff / 1000000.0;
                encryptTime += second ;

                gettimeofday(&timestart,NULL);
                cryptoObj_->generateHash(tempChunk.chunk.logicData, tempChunk.chunk.logicDataSize, tempChunk.chunk.chunkHash);
                memcpy(chunkHashList + currentBatchChunkNumber * CHUNK_HASH_SIZE, tempChunk.chunk.chunkHash, CHUNK_HASH_SIZE);
                gettimeofday(&timeend,NULL);
                diff = 1000000 * (timeend.tv_sec - timestart.tv_sec) + timeend.tv_usec - timestart.tv_usec;
                second = diff / 1000000.0;
                dupDetectionTime += second ;

                batchChunk.push_back(tempChunk);
                currentBatchChunkNumber++;
            }
        }
        if (currentBatchChunkNumber == powBatchSize || jobDoneFlag) {
            gettimeofday(&timestart,NULL);
            u_char serverResponse[sizeof(int) + sizeof(bool) * currentBatchChunkNumber];
            senderObj_->sendHashList(chunkHashList, currentBatchChunkNumber, serverResponse, netstatus);

            if (netstatus != SUCCESS) {
                cerr << "PowClient : server pow signed hash verify error, client mac = " << endl;
                PRINT_BYTE_ARRAY_POW_CLIENT(stderr, chunkHashList, CHUNK_HASH_SIZE);
                break;
            } else {
                int totalNeedChunkNumber;
                memcpy(&totalNeedChunkNumber, serverResponse, sizeof(int));
                bool requiredChunksList[currentBatchChunkNumber];
                memcpy(requiredChunksList, serverResponse + sizeof(int), sizeof(bool) * currentBatchChunkNumber);

                for (int i = 0; i < currentBatchChunkNumber; i++) {
                    if (requiredChunksList[i]) {
                        batchChunk[i].chunk.type = CHUNK_TYPE_NEED_UPLOAD;
                    }
                    senderObj_->insertMQ(batchChunk[i]);
                }
                gettimeofday(&timeend,NULL);
                diff = 1000000 * (timeend.tv_sec - timestart.tv_sec) + timeend.tv_usec - timestart.tv_usec;
                second = diff / 1000000.0;
                dupDetectionTime += second ;
            }
            currentBatchChunkNumber = 0;
            batchChunk.clear();
        }
        if (jobDoneFlag) {
            cout<<"powClient : encrypt time = "<<encryptTime<<endl;
            cout<<"powClient : duplicate detection time = "<<dupDetectionTime<<endl;
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


