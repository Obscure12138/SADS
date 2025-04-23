#include "keyClient.hpp"
#include "openssl/rsa.h"
#include <fstream>
#include <sys/time.h>

#define RSA_KEY_SIZE 128

extern Configure config;

struct timeval timestartKey;
struct timeval timeendKey;

void PRINT_BYTE_ARRAY_KEY_CLIENT(
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

KeyClient::KeyClient(powClient* powObjTemp)
{
    inputMQ_ = new messageQueue<Data_t>;
    powObj_ = powObjTemp;
    cryptoObj_ = new CryptoPrimitive();
    keyBatchSize_ = (int)config.getKeyBatchSize();
    keySecurityChannel_ = new ssl(config.getKeyServerIP(), config.getKeyServerPort(), CLIENTSIDE);
    sslConnection_ = keySecurityChannel_->sslConnect().second;
    clientID_ = config.getClientID();

    keyN_ = BN_new();
    fai_N = BN_new();
    bnCTX = BN_CTX_new();
    FILE* out;
    unsigned char prime[128];
    out = fopen("../prime","r+");
    fread(prime,sizeof(char),128,out);
    fclose(out);
    BN_bin2bn((const unsigned char*)prime, 128, keyN_);
    BN_copy(fai_N,keyN_);
    BN_sub_word(fai_N,1);

    // BIGNUM* r;
    // BIGNUM* inv;
    // BIGNUM* h;
    // BIGNUM* tmp;
    // unsigned char tmp1[512];
    // r = BN_new();
    // inv = BN_new();
    // h = BN_new();
    // tmp = BN_new();
    // BN_pseudo_rand(h,256,-1,0);
    // BN_pseudo_rand(r,256,-1,0);
    // BN_mod_inverse(inv,r,fai_N,bnCTX);
    // BN_mod_exp(tmp,h,r,keyN_,bnCTX);
    // int len = BN_bn2bin(tmp,tmp1);
    // cout<< len <<endl;
}

KeyClient::KeyClient( uint64_t keyGenNumber)
{
    inputMQ_ = new messageQueue<Data_t>;
    cryptoObj_ = new CryptoPrimitive();
    keyBatchSize_ = (int)config.getKeyBatchSize();
    keyGenNumber_ = keyGenNumber;
   // totalSimulatorThreadNumber_ = threadNumber;
    currentInitThreadNumber_ = 0;
    clientID_ = config.getClientID();
    keySecurityChannel_ = new ssl(config.getKeyServerIP(), config.getKeyServerPort(), CLIENTSIDE);
    sslConnection_ = keySecurityChannel_->sslConnect().second;
    keyN_ = BN_new();
    fai_N = BN_new();
    bnCTX = BN_CTX_new();
    FILE* out;
    unsigned char prime[128];
    out = fopen("../prime","r+");
    fread(prime,sizeof(char),128,out);
    fclose(out);
    BN_bin2bn((const unsigned char*)prime, 128, keyN_);
    BN_copy(fai_N,keyN_);
    BN_sub_word(fai_N,1);
}

KeyClient::~KeyClient()
{
    delete cryptoObj_;
    inputMQ_->~messageQueue();
    delete inputMQ_;
}

// bool KeyClient::outputKeyGenSimulatorRunningTime()
// {
//     uint64_t startTime = ~0, endTime = 0;
//     if (keyGenSimulatorStartTimeCounter_.size() != keyGenSimulatorEndTimeCounter_.size()) {
//         cerr << "KeyClient : key generate simulator time counter error" << endl;
//         return false;
//     }
//     for (int i = 0; i < keyGenSimulatorStartTimeCounter_.size(); i++) {
//         uint64_t startTimeTemp = 1000000 * keyGenSimulatorStartTimeCounter_[i].tv_sec + keyGenSimulatorStartTimeCounter_[i].tv_usec;
//         uint64_t endTimeTemp = 1000000 * keyGenSimulatorEndTimeCounter_[i].tv_sec + keyGenSimulatorEndTimeCounter_[i].tv_usec;
//         if (startTimeTemp < startTime) {
//             startTime = startTimeTemp;
//         }
//         if (endTimeTemp > endTime) {
//             endTime = endTimeTemp;
//         }
// #if SYSTEM_DEBUG_FLAG == 1
//         cerr << "Time Count : " << startTime << "\t" << startTimeTemp << "\t" << endTime << "\t" << endTimeTemp << endl;
// #endif
//     }
//     double second = (endTime - startTime) / 1000000.0;
//     cout << "KeyClient : key generate simulator working time = " << second << endl;
//     // #if SYSTEM_BREAK_DOWN == 1
//     //     cout << "KeyClient : key exchange encryption work time = " << keyExchangeEncTime << " s" << endl;
//     // #if KEY_GEN_METHOD_TYPE == KEY_GEN_SGX_CTR
//     //     cout << "KeyClient : key exchange mask generate work time = " << keyExchangeMaskGenerateTime << " s" << endl;
//     // #endif
//     // #endif
//     return true;
// }

#if KEY_GEN_METHOD_TYPE == KEY_GEN_SGX_CTR

bool KeyClient::initClientCTRInfo()
{
#if SYSTEM_BREAK_DOWN == 1
    gettimeofday(&timestartKey, NULL);
#endif // SYSTEM_BREAK_DOWN
    //read old counter
    string keyGenFileName = ".keyGenStore";
    ifstream keyGenStoreIn;
    keyGenStoreIn.open(keyGenFileName, std::ifstream::in | std::ifstream::binary);
    if (keyGenStoreIn.is_open()) {
        keyGenStoreIn.seekg(0, ios_base::end);
        int counterFileSize = keyGenStoreIn.tellg();
        keyGenStoreIn.seekg(0, ios_base::beg);
        if (counterFileSize != 16) {
            cerr << "KeyClient : stored old counter file size error" << endl;
            return false;
        } else {
            char readBuffer[16];
            keyGenStoreIn.read(readBuffer, 16);
            keyGenStoreIn.close();
            if (keyGenStoreIn.gcount() != 16) {
                cerr << "KeyClient : read old counter file size error" << endl;
            } else {
                memcpy(nonce_, readBuffer, 12);
                memcpy(&counter_, readBuffer + 12, sizeof(uint32_t));
#if SYSTEM_DEBUG_FLAG == 1
                cerr << "KeyClient : Read old counter file : " << keyGenFileName << " success, the original counter = " << counter_ << ", nonce = " << endl;
                PRINT_BYTE_ARRAY_KEY_CLIENT(stderr, nonce_, 12);
#endif
            }
        }
    } else {
    nonceUsedRetry:
#if MULTI_CLIENT_UPLOAD_TEST == 1
        memset(nonce_, clientID_, 12);
#else
        srand(time(NULL));
        for (int i = 0; i < 12 / sizeof(int); i++) {
            int randomNumber = rand();
            memcpy(nonce_ + i * sizeof(int), &randomNumber, sizeof(int));
        }
#endif
#if SYSTEM_DEBUG_FLAG == 1
        cerr << "KeyClient : Can not open old counter file : \"" << keyGenFileName << "\", Directly reset counter to 0, generate nonce = " << endl;
        PRINT_BYTE_ARRAY_KEY_CLIENT(stderr, nonce_, 12);
#endif
    }
    // done
    NetworkHeadStruct_t initHead, responseHead;
    initHead.clientID = clientID_;
    initHead.dataSize = 48;
    initHead.messageType = KEY_GEN_UPLOAD_CLIENT_INFO;
    char initInfoBuffer[sizeof(NetworkHeadStruct_t) + initHead.dataSize]; // clientID & nonce & counter
    char responseBuffer[sizeof(NetworkHeadStruct_t)];
    memcpy(initInfoBuffer, &initHead, sizeof(NetworkHeadStruct_t));
    u_char tempCipherBuffer[16], tempPlaintBuffer[16];
    memcpy(tempPlaintBuffer, &counter_, sizeof(uint32_t));
    memcpy(tempPlaintBuffer + sizeof(uint32_t), nonce_, 16 - sizeof(uint32_t));
    cryptoObj_->keyExchangeEncrypt(tempPlaintBuffer, 16, keyExchangeKey_, keyExchangeKey_, tempCipherBuffer);
    memcpy(initInfoBuffer + sizeof(NetworkHeadStruct_t), tempCipherBuffer, 16);
    cryptoObj_->sha256Hmac(tempCipherBuffer, 16, (u_char*)initInfoBuffer + sizeof(NetworkHeadStruct_t) + 16, keyExchangeKey_, 32);
    if (!keySecurityChannel_->send(sslConnection_, initInfoBuffer, sizeof(NetworkHeadStruct_t) + initHead.dataSize)) {
        cerr << "KeyClient: send init information error" << endl;
        return false;
    } else {
        int recvSize;
        if (!keySecurityChannel_->recv(sslConnection_, responseBuffer, recvSize)) {
            cerr << "KeyClient: recv init information status error" << endl;
            return false;
        } else {
            memcpy(&responseHead, responseBuffer, sizeof(NetworkHeadStruct_t));
#if SYSTEM_DEBUG_FLAG == 1
            cerr << "KeyClient : recv key server response, message type = " << responseHead.messageType << endl;
            PRINT_BYTE_ARRAY_KEY_CLIENT(stderr, responseBuffer, sizeof(NetworkHeadStruct_t));
#endif
            if (responseHead.messageType == CLIENT_COUNTER_REST) {
                cerr << "KeyClient : key server counter error, reset client counter to 0" << endl;
                counter_ = 0;
#if SYSTEM_BREAK_DOWN == 1
                gettimeofday(&timeendKey, NULL);
                int diff = 1000000 * (timeendKey.tv_sec - timestartKey.tv_sec) + timeendKey.tv_usec - timestartKey.tv_usec;
                double second = diff / 1000000.0;
                cout << "KeyClient : init ctr mode key exchange time = " << second << " s" << endl;
#endif // SYSTEM_BREAK_DOWN
                return true;
            } else if (responseHead.messageType == NONCE_HAS_USED) {
                cerr << "KeyClient: nonce has used, goto retry" << endl;
                goto nonceUsedRetry;
            } else if (responseHead.messageType == ERROR_RESEND) {
                cerr << "KeyClient: hmac error, goto retry" << endl;
                goto nonceUsedRetry;
            } else if (responseHead.messageType == SUCCESS) {
                cerr << "KeyClient : init information success, start key generate" << endl;
#if SYSTEM_BREAK_DOWN == 1
                gettimeofday(&timeendKey, NULL);
                int diff = 1000000 * (timeendKey.tv_sec - timestartKey.tv_sec) + timeendKey.tv_usec - timestartKey.tv_usec;
                double second = diff / 1000000.0;
                cout << "KeyClient : init ctr mode key exchange time = " << second << " s" << endl;
#endif // SYSTEM_BREAK_DOWN
                return true;
            }
        }
    }
}

bool KeyClient::saveClientCTRInfo()
{
#if SYSTEM_BREAK_DOWN == 1
    gettimeofday(&timestartKey, NULL);
#endif // SYSTEM_BREAK_DOWN
    string keyGenFileName = ".keyGenStore";
    ofstream counterOut;
    counterOut.open(keyGenFileName, std::ofstream::out | std::ofstream::binary);
    if (!counterOut.is_open()) {
        cerr << "KeyClient : Can not open counter store file : " << keyGenFileName << endl;
        return false;
    } else {
        char writeBuffer[16];
        memcpy(writeBuffer, nonce_, 12);
        memcpy(writeBuffer + 12, &counter_, sizeof(uint32_t));
        counterOut.write(writeBuffer, 16);
        counterOut.close();
        cerr << "KeyClient : Stored current counter file : " << keyGenFileName << endl;
#if SYSTEM_BREAK_DOWN == 1
        gettimeofday(&timeendKey, NULL);
        int diff = 1000000 * (timeendKey.tv_sec - timestartKey.tv_sec) + timeendKey.tv_usec - timestartKey.tv_usec;
        double second = diff / 1000000.0;
        cout << "KeyClient : save ctr mode status time = " << second << " s" << endl;
#endif // SYSTEM_BREAK_DOWN
        return true;
    }
}

#endif
void KeyClient::runKeyGenSimulator()
{
    struct timeval timestartKeySimulatorThread;
    struct timeval timeendKeySimulatorThread;
#if SYSTEM_BREAK_DOWN == 1
    struct timeval timestartKeySimulator;
    struct timeval timeendKeySimulator;
    double threadWorkTime = 0;
    double keyGenTime = 0;
    double chunkHashGenerateTime = 0;
    double keyExchangeTime = 0;
#endif
	fstream out("result",ios::out|ios::app);
    long diff;
    double second = 0;
    double decorateTime = 0, exchangeTime = 0, eliminationTime = 0;
    int batchNumber = 0;
    int currentKeyGenNumber = 0;
    u_char chunkKey[RSA_KEY_SIZE * keyBatchSize_];
    u_char decoratedHash[sizeof(int) + (CHUNK_HASH_SIZE + RSA_KEY_SIZE) * keyBatchSize_];
    u_char chunkHash[CHUNK_HASH_SIZE * keyGenNumber_];
    bool JobDoneFlag = false;
    fstream in("/home/nk629/fsl/fslhomes-user000-2014-10-01/fslhomes-user000-2014-10-01.8kb.hash.anon.hash",ios::in);
    in.read((char*)chunkHash, CHUNK_HASH_SIZE * keyGenNumber_);
    in.close();
    BIGNUM* r = BN_new();
    BIGNUM* inv = BN_new();
    BN_pseudo_rand(r,256,-1,0);
    BN_mod_inverse(inv,r,fai_N,bnCTX);
    while (true) {

        if (currentKeyGenNumber < keyGenNumber_) {
            gettimeofday(&timestartKeySimulatorThread, NULL);
            memcpy(decoratedHash + sizeof(int)+ batchNumber *  (CHUNK_HASH_SIZE + RSA_KEY_SIZE), chunkHash + batchNumber * CHUNK_HASH_SIZE, CHUNK_HASH_SIZE);
            DecorateFP(r,chunkHash + currentKeyGenNumber * CHUNK_HASH_SIZE, decoratedHash + sizeof(int) + batchNumber * (CHUNK_HASH_SIZE + RSA_KEY_SIZE) +  CHUNK_HASH_SIZE);
            gettimeofday(&timeendKeySimulatorThread, NULL);
            diff = 1000000 * (timeendKeySimulatorThread.tv_sec - timestartKeySimulatorThread.tv_sec) + timeendKeySimulatorThread.tv_usec - timestartKeySimulatorThread.tv_usec;
            second += diff / 1000000.0;
            decorateTime += diff / 1000000.0;
            batchNumber++;
            currentKeyGenNumber++;
        } else {
            JobDoneFlag = true;
        }
        if (batchNumber == keyBatchSize_ || JobDoneFlag) {
            if (batchNumber == 0) {
                break;
            }
            int batchedKeySize = 0;
            memcpy(decoratedHash, &clientID_, sizeof(int));
            gettimeofday(&timestartKeySimulatorThread, NULL);
            bool keyExchangeStatus = keyExchange(decoratedHash, batchNumber, chunkKey, batchedKeySize);
            gettimeofday(&timeendKeySimulatorThread, NULL);
            diff = 1000000 * (timeendKeySimulatorThread.tv_sec - timestartKeySimulatorThread.tv_sec) + timeendKeySimulatorThread.tv_usec - timestartKeySimulatorThread.tv_usec;
            second += diff / 1000000.0;
            exchangeTime += diff / 1000000.0;
            if (keyExchangeStatus == false) {
                cerr << "KeyClient : key generate error, thread exit" << endl;
                break;
            }
            u_char tmpKey[RSA_KEY_SIZE + CHUNK_HASH_SIZE * 2];
            for(int i=0;i<batchNumber;i++)
            {
                gettimeofday(&timestartKeySimulatorThread, NULL);
                Elimination(inv,chunkKey + i * RSA_KEY_SIZE, tmpKey);
                memcpy(tmpKey + RSA_KEY_SIZE, chunkHash + currentKeyGenNumber * CHUNK_HASH_SIZE, CHUNK_HASH_SIZE);
                memcpy(tmpKey + RSA_KEY_SIZE + CHUNK_HASH_SIZE, chunkHash + currentKeyGenNumber * CHUNK_HASH_SIZE, CHUNK_HASH_SIZE);
                SHA256(tmpKey, RSA_KEY_SIZE + CHUNK_HASH_SIZE * 2,tmpKey);
                gettimeofday(&timeendKeySimulatorThread, NULL);
                diff = 1000000 * (timeendKeySimulatorThread.tv_sec - timestartKeySimulatorThread.tv_sec) + timeendKeySimulatorThread.tv_usec - timestartKeySimulatorThread.tv_usec;
                second += diff / 1000000.0;
                eliminationTime += diff / 1000000.0;
            }
            memset(decoratedHash, 0, RSA_KEY_SIZE * keyBatchSize_);
            memset(chunkKey, 0, RSA_KEY_SIZE * keyBatchSize_);
            batchNumber = 0;
        }
        if (JobDoneFlag) {
            break;
        }
    }
    cout<<"generate "<<keyGenNumber_<<" keys time : "<<second<<" s"<<endl;
    cout<<"decorateTime = "<<decorateTime<<endl;
    cout<<"exchangeTime = "<<exchangeTime<<endl;
    cout<<"eliminationTime = "<<eliminationTime<<endl;
    out<<second<<endl;
    out.close();
    return;
}

void KeyClient::run()
{

#if SYSTEM_BREAK_DOWN == 1
#endif // SYSTEM_BREAK_DOWN
    double keyGenTime = 0;
    double keyVerifyTime = 0;
    long diff;
    double second;
    struct timeval timestart;
    struct timeval timeend;
    double decorateTime = 0, exchangeTime = 0, eliminationTime = 0;
#if KEY_GEN_METHOD_TYPE == KEY_GEN_SGX_CTR
    bool initStatus = initClientCTRInfo();
    if (initStatus != true) {
        cerr << "KeyClient : init to key server error, client exit" << endl;
        exit(0);
    }
#if SYSTEM_DEBUG_FLAG == 1
    else {
        cerr << "KeyClient : init to key server success" << endl;
    }
#endif
#endif
    vector<Data_t> batchList;
    int batchNumber = 0;
    u_char chunkKey[RSA_KEY_SIZE * keyBatchSize_];
    u_char RSABuffer[sizeof(int) + (RSA_KEY_SIZE + CHUNK_HASH_SIZE) * keyBatchSize_];
    bool JobDoneFlag = false;
    NetworkHeadStruct_t dataHead;
    dataHead.clientID = clientID_;
    dataHead.messageType = KEY_GEN_UPLOAD_CHUNK_HASH;
    BIGNUM* r;
    BIGNUM* inv;
    r = BN_new();
    inv = BN_new();
	BN_bin2bn((const unsigned char*)"F2FED9CD0F1DB336AF0419EA1A5A602282D1557CB01486B5023833FB73F0F6",32,r);
	cout<<endl;
    BN_mod_inverse(inv,r,fai_N,bnCTX);
    Data_t tempChunk;
    while (true) {
        if (inputMQ_->done_ && inputMQ_->isEmpty()) {
            JobDoneFlag = true;
        }
        if (extractMQ(tempChunk)) {
            if (tempChunk.dataType == DATA_TYPE_RECIPE) {
                powObj_->insertMQ(tempChunk);
                continue;
            }

            cryptoObj_->generateHash(tempChunk.chunk.logicData, tempChunk.chunk.logicDataSize, tempChunk.chunk.encryptKey);
            powObj_->insertMQ(tempChunk);
            continue;

            batchList.push_back(tempChunk);
            gettimeofday(&timestart,NULL);

            memcpy(RSABuffer + sizeof(int) + batchNumber * (RSA_KEY_SIZE + CHUNK_HASH_SIZE), tempChunk.chunk.feature, CHUNK_HASH_SIZE);
            DecorateFP(r, tempChunk.chunk.chunkHash, RSABuffer + sizeof(int) + batchNumber * (CHUNK_HASH_SIZE + RSA_KEY_SIZE) + CHUNK_HASH_SIZE);
            
            gettimeofday(&timeend,NULL);
            diff = 1000000 * (timeend.tv_sec - timestart.tv_sec) + timeend.tv_usec - timestart.tv_usec;
            second = diff / 1000000.0;
            keyGenTime += second ;
            decorateTime += diff / 1000000.0;
            batchNumber++;
        }
        if (batchNumber == keyBatchSize_ || JobDoneFlag) {
            if (batchNumber == 0) {
                bool editJobDoneFlagStatus = powObj_->editJobDoneFlag();
                if (!editJobDoneFlagStatus) {
                    cerr << "KeyClient : error to set job done flag for encoder" << endl;
                }
                break;
            }
            int batchedKeySize = 0;
#if SYSTEM_BREAK_DOWN == 1
            gettimeofday(&timestartKey, NULL);
#endif
#if KEY_GEN_METHOD_TYPE == KEY_GEN_SGX_CTR
            dataHead.dataSize = batchNumber * CHUNK_HASH_SIZE;
            bool keyExchangeStatus = keyExchange(chunkHash, batchNumber, chunkKey, batchedKeySize, dataHead);
            counter_ += batchNumber * 4;
#else
            memcpy(RSABuffer, &clientID_, sizeof(int));
            gettimeofday(&timestart,NULL);
            bool keyExchangeStatus = keyExchange(RSABuffer, batchNumber, chunkKey, batchedKeySize);
            gettimeofday(&timeend,NULL);
            diff = 1000000 * (timeend.tv_sec - timestart.tv_sec) + timeend.tv_usec - timestart.tv_usec;
            second = diff / 1000000.0;
            keyGenTime += second ;
            exchangeTime += diff / 1000000.0;
#endif
#if SYSTEM_BREAK_DOWN == 1
            gettimeofday(&timeendKey, NULL);
            diff = 1000000 * (timeendKey.tv_sec - timestartKey.tv_sec) + timeendKey.tv_usec - timestartKey.tv_usec;
            second = diff / 1000000.0;
            keyGenTime += second;
#endif
            if (!keyExchangeStatus) {
                cerr << "KeyClient : error get key for " << setbase(10) << batchNumber << " chunks" << endl;
                return;
            } else {
                for (int i = 0; i < batchNumber; i++) {

                    // gettimeofday(&timestart,NULL);
                    // if(!Verify(RSABuffer + sizeof(int) + i*(RSA_KEY_SIZE + CHUNK_HASH_SIZE) + CHUNK_HASH_SIZE, batchList[i].chunk.feature, chunkKey + i * RSA_KEY_SIZE))
                    // {
                    //    cout<<"KeyClient : Verify Key Fail"<<endl;
                    //   return;
                    // }
                    // gettimeofday(&timeend,NULL);
                    // diff = 1000000 * (timeend.tv_sec - timestart.tv_sec) + timeend.tv_usec - timestart.tv_usec;
                    // second = diff / 1000000.0;
                    // keyVerifyTime += second ;

                    gettimeofday(&timestart,NULL);

                    u_char tmpRSAKey[RSA_KEY_SIZE + CHUNK_HASH_SIZE * 2] = {0};
                    Elimination(inv, chunkKey + i * RSA_KEY_SIZE, tmpRSAKey);
                    memcpy(tmpRSAKey + RSA_KEY_SIZE, batchList[i].chunk.feature,CHUNK_HASH_SIZE);
                    memcpy(tmpRSAKey + RSA_KEY_SIZE + CHUNK_HASH_SIZE, batchList[i].chunk.chunkHash, CHUNK_HASH_SIZE);
                    SHA256(tmpRSAKey, RSA_KEY_SIZE + CHUNK_HASH_SIZE * 2, batchList[i].chunk.encryptKey);
                    
                    gettimeofday(&timeend,NULL);
                    diff = 1000000 * (timeend.tv_sec - timestart.tv_sec) + timeend.tv_usec - timestart.tv_usec;
                    second = diff / 1000000.0;
                    keyGenTime += second ;
                    eliminationTime += diff / 1000000.0;
                    powObj_->insertMQ(batchList[i]);
                }
                batchList.clear();
                memset(RSABuffer, 0, (RSA_KEY_SIZE + CHUNK_HASH_SIZE)* keyBatchSize_);
                memset(chunkKey, 0, RSA_KEY_SIZE * keyBatchSize_);
                batchNumber = 0;
            }
        }
        if (JobDoneFlag) {
            bool editJobDoneFlagStatus = powObj_->editJobDoneFlag();
            if (!editJobDoneFlagStatus) {
                cerr << "KeyClient : error to set job done flag for encoder" << endl;
            }
            cout<<"KeyClient : key generate time = "<<keyGenTime<<endl;
            cout<<"decorateTime = "<<decorateTime<<endl;
            cout<<"exchangeTime = "<<exchangeTime<<endl;
            cout<<"eliminationTime = "<<eliminationTime<<endl;
            break;
        }
    }
#if SYSTEM_BREAK_DOWN == 1
#if KEY_GEN_METHOD_TYPE == KEY_GEN_SGX_CTR
    cout << "KeyClient : key exchange mask generate work time = " << keyExchangeMaskGenerateTime << " s" << endl;
#endif
    cout << "KeyClient : key exchange encrypt/decrypt work time = " << keyExchangeEncTime << " s" << endl;
    cout << "KeyClient : key generate total work time = " << keyGenTime << " s" << endl;
    cout << "KeyClient : chunk encryption work time = " << chunkContentEncryptionTime << " s" << endl;
#endif
#if KEY_GEN_METHOD_TYPE == KEY_GEN_SGX_CTR
    bool saveStatus = saveClientCTRInfo();
    if (saveStatus != true) {
        cerr << "KeyClient : save ctr mode information error" << endl;
        exit(0);
    }
#if SYSTEM_DEBUG_FLAG == 1
    else {
        cerr << "KeyClient : save ctr mode information success" << endl;
    }
#endif
#endif
    return;
}

bool KeyClient::keyExchange(u_char* batchHashList, int batchNumber, u_char* batchKeyList, int& batchkeyNumber)
{
    if (!keySecurityChannel_->send(sslConnection_, (char*)batchHashList, sizeof(int)  + (RSA_KEY_SIZE + CHUNK_HASH_SIZE) * batchNumber)) {
        cerr << "KeyClient: send socket error" << endl;
        return false;
    }

    int recvSize;
    if (!keySecurityChannel_->recv(sslConnection_, (char*)batchKeyList, recvSize)) {
        cerr << "KeyClient: recv socket error" << endl;
        return false;
    }
    return true;
}

// bool KeyClient::keyExchange(u_char* batchHashList, int batchNumber, u_char* batchKeyList, int& batchkeyNumber, ssl* securityChannel, SSL* sslConnection, CryptoPrimitive* cryptoObj)
// {
//     u_char sendHash[CHUNK_HASH_SIZE * batchNumber + 32];
//     // #if SYSTEM_BREAK_DOWN == 1
//     //     struct timeval timestartKey_enc;
//     //     struct timeval timeendKey_enc;
//     //     gettimeofday(&timestartKey_enc, NULL);
//     // #endif
//     cryptoObj->keyExchangeEncrypt(batchHashList, batchNumber * CHUNK_HASH_SIZE, keyExchangeKey_, keyExchangeKey_, sendHash);
//     cryptoObj->sha256Hmac(sendHash, CHUNK_HASH_SIZE * batchNumber, sendHash + CHUNK_HASH_SIZE * batchNumber, keyExchangeKey_, 32);
// #if SYSTEM_DEBUG_FLAG == 1
//     cerr << "KeyClient : send key exchange hmac = " << endl;
//     PRINT_BYTE_ARRAY_KEY_CLIENT(stderr, sendHash + CHUNK_HASH_SIZE * batchNumber, 32);
// #endif
//     // #if SYSTEM_BREAK_DOWN == 1
//     //     gettimeofday(&timeendKey_enc, NULL);
//     //     long diff = 1000000 * (timeendKey_enc.tv_sec - timestartKey_enc.tv_sec) + timeendKey_enc.tv_usec - timestartKey_enc.tv_usec;
//     //     double second = diff / 1000000.0;
//     //     mutexkeyGenerateSimulatorEncTime_.lock();
//     //     keyExchangeEncTime += second;
//     //     mutexkeyGenerateSimulatorEncTime_.unlock();
//     // #endif
//     if (!securityChannel->send(sslConnection, (char*)sendHash, CHUNK_HASH_SIZE * batchNumber + 32)) {
//         cerr << "KeyClient: send socket error" << endl;
//         return false;
//     }
//     u_char recvBuffer[CHUNK_ENCRYPT_KEY_SIZE * batchNumber + 32];
//     int recvSize;
//     if (!securityChannel->recv(sslConnection, (char*)recvBuffer, recvSize)) {
//         cerr << "KeyClient: recv socket error" << endl;
//         return false;
//     }
//     // #if SYSTEM_BREAK_DOWN == 1
//     //     gettimeofday(&timestartKey_enc, NULL);
//     // #endif
//     u_char hmac[32];
//     cryptoObj->sha256Hmac(recvBuffer, CHUNK_HASH_SIZE * batchNumber, hmac, keyExchangeKey_, 32);
//     if (memcmp(hmac, recvBuffer + batchNumber * CHUNK_HASH_SIZE, 32) != 0) {
//         cerr << "KeyClient : recved keys hmac error" << endl;
// #if SYSTEM_DEBUG_FLAG == 1
//         cerr << "KeyClient : recv key exchange hmac = " << endl;
//         PRINT_BYTE_ARRAY_KEY_CLIENT(stderr, recvBuffer + CHUNK_HASH_SIZE * batchNumber, 32);
//         cerr << "KeyClient : client computed key exchange hmac = " << endl;
//         PRINT_BYTE_ARRAY_KEY_CLIENT(stderr, hmac, 32);
// #endif
//         return false;
//     }
//     cryptoObj->keyExchangeDecrypt(recvBuffer, batchkeyNumber * CHUNK_ENCRYPT_KEY_SIZE, keyExchangeKey_, keyExchangeKey_, batchKeyList);
//     // #if SYSTEM_BREAK_DOWN == 1
//     //     gettimeofday(&timeendKey_enc, NULL);
//     //     diff = 1000000 * (timeendKey_enc.tv_sec - timestartKey_enc.tv_sec) + timeendKey_enc.tv_usec - timestartKey_enc.tv_usec;
//     //     second = diff / 1000000.0;
//     //     mutexkeyGenerateSimulatorEncTime_.lock();
//     //     keyExchangeEncTime += second;
//     //     mutexkeyGenerateSimulatorEncTime_.unlock();
//     // #endif
//     return true;
// }


bool KeyClient::insertMQ(Data_t& newChunk)
{
    return inputMQ_->push(newChunk);
}

bool KeyClient::extractMQ(Data_t& newChunk)
{
    return inputMQ_->pop(newChunk);
}

bool KeyClient::editJobDoneFlag()
{
    inputMQ_->done_ = true;
    if (inputMQ_->done_) {
        return true;
    } else {
        return false;
    }
}

void KeyClient::DecorateFP(BIGNUM* r, uint8_t* fp, uint8_t* outputBuffer)
{
    BIGNUM* tmp = BN_new();
    BIGNUM* h = BN_new();
    unsigned char result[RSA_KEY_SIZE];
    BN_bin2bn(fp,CHUNK_HASH_SIZE,h);
    BN_mod_exp(tmp,h,r,keyN_,bnCTX);
    BN_bn2bin(tmp,result +  (RSA_KEY_SIZE - BN_num_bytes(tmp)));
    memcpy(outputBuffer, result , RSA_KEY_SIZE);
    BN_free(tmp);
    BN_free(h);
    return;
}

void KeyClient::Elimination(BIGNUM* inv, uint8_t*key , uint8_t* outputBuffer)
{
    BIGNUM* tmp = BN_new();
    BIGNUM* h = BN_new();
    unsigned char result[RSA_KEY_SIZE];
    BN_bin2bn(key,RSA_KEY_SIZE,h);
    BN_mod_exp(tmp,h,inv,keyN_,bnCTX);
    BN_bn2bin(tmp,result +  (RSA_KEY_SIZE - BN_num_bytes(tmp)));
    memcpy(outputBuffer, result , RSA_KEY_SIZE);
    BN_free(tmp);
    BN_free(h);
    return ;
}
