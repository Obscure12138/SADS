#include "keyServer.hpp"
#include <fcntl.h>
#include <sys/time.h>
extern Configure config;
#define RSA_KEY_SIZE 128
#define INIT_DELAY 1
#define USER_NUMBER 3
int Usercount = 0;

void PRINT_BYTE_ARRAY_KEY_SERVER(
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

keyServer::keyServer(ssl* keyServerSecurityChannelTemp)
{
    clientThreadCount_ = 0;
   
   bnCTX = BN_CTX_new();
   keyN_ = BN_new();
   sk = BN_new();
   FILE* in;
   unsigned char prime[128];
   in = fopen("../prime","r+");
   fread(prime,sizeof(char),128,in);
   fclose(in);
   BN_bin2bn(prime,128,keyN_);
   BN_set_word(sk,12345);
}

keyServer::~keyServer()
{
    delete keySecurityChannel_;
}

void keyServer::updateEpoch()
{
    for(auto it = SFList.begin();it != SFList.end();it++)
    {
        it->second.delay = INIT_DELAY;
        it->second.fpSet.clear();
        it->second.historyCount.push_back(it->second.currentEpochCount);
        if(it->second.historyCount.size() > 2)
        {
            it->second.limit = true;
            int s = it->second.historyCount.size();
            double mean = (it->second.historyCount[s-1] + it->second.historyCount[s-2] + it->second.historyCount[s-3]) / 3;
            double variance = pow(mean - it->second.historyCount[s-1], 2) + pow(mean - it->second.historyCount[s-2], 2) + pow(mean - it->second.historyCount[s-3], 2);
            variance = sqrt(variance);
            it->second.threshold = mean + 3 * variance;
            it->second.maxDelay = ((24*60*60)*1000) / it->second.threshold ;
        }
        it->second.currentEpochCount = 0;
    }
}


#if KEY_GEN_METHOD_TYPE == KEY_GEN_SGX_CFB

void keyServer::runKeyGenerateThread(SSL* connection)
{
#if SYSTEM_BREAK_DOWN == 1
    struct timeval timestart;
    struct timeval timeend;
    double keyGenTime = 0;
    long diff;
    double second;
#endif
    multiThreadCountMutex_.lock();
    clientThreadCount_++;
    Usercount++;
    multiThreadCountMutex_.unlock();
    uint64_t currentThreadkeyGenerationNumber = 0;
    u_char key[config.getKeyBatchSize() * RSA_KEY_SIZE]={0};
    u_char hash[sizeof(int) + config.getKeyBatchSize() * (RSA_KEY_SIZE + CHUNK_HASH_SIZE)];
    u_char buffer[RSA_KEY_SIZE];
    uint64_t currentClientDelay = 0;
    BIGNUM* h;
    BIGNUM* sf;
    BIGNUM* tmp;
    h = BN_new();
    sf = BN_new();
    tmp = BN_new();
    while (true) {
        int recvSize = 0;
        if (!keySecurityChannel_->recv(connection, (char*)hash, recvSize)) {
            multiThreadCountMutex_.lock();
            clientThreadCount_--;
            cerr << "keyServer : Thread exit due to client disconnect， current client counter = " << clientThreadCount_ << endl;
            multiThreadCountMutex_.unlock();
            break;
        }
        int currentClientID;
        memcpy(&currentClientID, hash, sizeof(int));
        int recvNumber = (recvSize - sizeof(int)) / (RSA_KEY_SIZE + CHUNK_HASH_SIZE);
        if (recvNumber == 0) {
            multiThreadCountMutex_.lock();
            clientThreadCount_--;
            cerr << "keyServer : Thread exit due to client disconnect， current client counter = " << clientThreadCount_ << endl;
            multiThreadCountMutex_.unlock();
            break;
        }
        for(int i=0 ; i<recvNumber ; i++)
        {   
            // string SF((char*)hash + sizeof(int) + i*(RSA_KEY_SIZE + CHUNK_HASH_SIZE), CHUNK_HASH_SIZE);
            // if(SFList.find(SF) == SFList.end())
            // {
            //     string FP((char*)hash + sizeof(int) + i*(RSA_KEY_SIZE + CHUNK_HASH_SIZE) + CHUNK_HASH_SIZE, RSA_KEY_SIZE);
            //     limitInfo tmpInfo;
            //     tmpInfo.threshold = 0;
            //     tmpInfo.currentEpochCount = 1;
            //     tmpInfo.lastUserID = currentClientID;
            //     tmpInfo.limit = false;
            //     tmpInfo.multiuser = true;
            //     tmpInfo.delay = INIT_DELAY;
            //     tmpInfo.maxDelay = 0;
            //     tmpInfo.fpSet.insert(FP);
            //     SFList.insert(make_pair(SF,tmpInfo));
            // }
            // else{
            //     string FP((char*)hash + sizeof(int) + i*(RSA_KEY_SIZE + CHUNK_HASH_SIZE)+ CHUNK_HASH_SIZE,RSA_KEY_SIZE);
            //     if(SFList[SF].lastUserID != currentClientID)
            //     {
            //         SFList[SF].multiuser = true;
            //     }
            //     if(SFList[SF].fpSet.find(FP) == SFList[SF].fpSet.end())
            //     {
            //         SFList[SF].fpSet.insert(FP);
            //         SFList[SF].currentEpochCount++;
            //         if(SFList[SF].limit && SFList[SF].multiuser)
            //         {
            //             //sleep((double)(SFList[SF].delay / 1000));
            //             currentClientDelay += SFList[SF].delay;
            //             if(SFList[SF].delay < SFList[SF].maxDelay)
            //             {
            //                 SFList[SF].delay = (SFList[SF].delay << 1) < SFList[SF].maxDelay ? (SFList[SF].delay << 1) : SFList[SF].maxDelay ;
            //             }
            //         }
            //     }
            // }
            memset(buffer,0,RSA_KEY_SIZE);
            BN_bin2bn(hash + sizeof(int) + i * (RSA_KEY_SIZE + CHUNK_HASH_SIZE), CHUNK_HASH_SIZE,sf);
            BN_bin2bn(hash + sizeof(int) + i*(RSA_KEY_SIZE + CHUNK_HASH_SIZE) + CHUNK_HASH_SIZE, RSA_KEY_SIZE,h);
            BN_mod_add(sf,sf,sk,keyN_,bnCTX);
            BN_mod_inverse(sf,sf,keyN_,bnCTX);
            BN_mod_exp(tmp,h,sf,keyN_,bnCTX);
            BN_bn2bin(tmp,buffer + (RSA_KEY_SIZE - BN_num_bytes(tmp)));
            memcpy(key + i* RSA_KEY_SIZE,buffer, RSA_KEY_SIZE);
        }

        multiThreadMutex_.lock();
        keyGenerateCount_ += recvNumber;
        multiThreadMutex_.unlock();
        currentThreadkeyGenerationNumber += recvNumber;
        if (!keySecurityChannel_->send(connection, (char*)key, recvNumber * RSA_KEY_SIZE)) {
            cerr << "KeyServer : error send back chunk key to client" << endl;
            multiThreadCountMutex_.lock();
            clientThreadCount_--;
            cerr << "keyServer : Thread exit due to client disconnect， current client counter = " << clientThreadCount_ << endl;
            multiThreadCountMutex_.unlock();
            break;
        }                                     
    }
    cout<<"current client delay = "<<currentClientDelay<<"ms"<<endl;
    if(Usercount == USER_NUMBER)
    {
        Usercount = 0;
        updateEpoch();
    }
    return;
}

#elif KEY_GEN_METHOD_TYPE == KEY_GEN_SGX_CTR

void keyServer::runCTRModeMaskGenerate()
{
#if SYSTEM_BREAK_DOWN == 1
    struct timeval timestart;
    struct timeval timeend;
    long diff;
    double second;
#endif
    while (true) {
        boost::xtime xt;
        boost::xtime_get(&xt, boost::TIME_UTC_);
        xt.sec = 5;
        boost::thread::sleep(xt);
        if (raRequestFlag_ == false && offlineGenerateFlag_ == true && clientThreadCount_ == 0) {
            multiThreadCountMutex_.lock();
            mutexSessionKeyUpdate.lock();
            cerr << "KeyServer : start offlien mask generate" << endl;
#if SYSTEM_BREAK_DOWN == 1
            gettimeofday(&timestart, 0);
#endif
            client->maskGenerate();
#if SYSTEM_BREAK_DOWN == 1
            gettimeofday(&timeend, 0);
            diff = 1000000 * (timeend.tv_sec - timestart.tv_sec) + timeend.tv_usec - timestart.tv_usec;
            second = diff / 1000000.0;
            cout << "KeyServer : offline mask generate time = " << second << " s" << endl;
#endif
            offlineGenerateFlag_ = false;
            cerr << "KeyServer : offlien mask generate done" << endl;
            mutexSessionKeyUpdate.unlock();
            multiThreadCountMutex_.unlock();
        }
    }
}

void keyServer::runKeyGenerateThread(SSL* connection)
{
#if SYSTEM_BREAK_DOWN == 1
    struct timeval timestart;
    struct timeval timeend;
    double keyGenTime = 0;
    long diff;
    double second;
#endif
    multiThreadCountMutex_.lock();
    clientThreadCount_++;
    offlineGenerateFlag_ = false;
    multiThreadCountMutex_.unlock();
    int recvSize = 0;
    uint64_t currentThreadkeyGenerationNumber = 0;
#if SYSTEM_BREAK_DOWN == 1
    gettimeofday(&timestart, 0);
#endif
    cerr << "KeyServer : start recv init messages" << endl;
    NetworkHeadStruct_t netHead;
    char initInfoBuffer[48 + sizeof(NetworkHeadStruct_t)]; // clientID & nonce & counter
    while (true) {
        if (keySecurityChannel_->recv(connection, initInfoBuffer, recvSize)) {
            memcpy(&netHead, initInfoBuffer, sizeof(NetworkHeadStruct_t));
            u_char cipherBuffer[16], hmacbuffer[32];
            memcpy(cipherBuffer, initInfoBuffer + sizeof(NetworkHeadStruct_t), 16);
            memcpy(hmacbuffer, initInfoBuffer + sizeof(NetworkHeadStruct_t) + 16, 32);
            multiThreadMutex_.lock();
#if SYSTEM_DEBUG_FLAG == 1
            cout << "KeyServer : modify client info for client = " << netHead.clientID << endl;
#endif
            int modifyClientInfoStatus = client->modifyClientStatus(netHead.clientID, cipherBuffer, hmacbuffer);
#if SYSTEM_DEBUG_FLAG == 1
            cout << "KeyServer : modify client info done for client = " << netHead.clientID << endl;
#endif
            multiThreadMutex_.unlock();
            if (modifyClientInfoStatus == SUCCESS || modifyClientInfoStatus == CLIENT_COUNTER_REST) {
                char responseBuffer[sizeof(NetworkHeadStruct_t)];
                NetworkHeadStruct_t responseHead;
                responseHead.clientID = netHead.clientID;
                responseHead.dataSize = 0;
                responseHead.messageType = modifyClientInfoStatus;
                int sendSize = sizeof(NetworkHeadStruct_t);
                memcpy(responseBuffer, &responseHead, sizeof(NetworkHeadStruct_t));
                keySecurityChannel_->send(connection, responseBuffer, sendSize);
                break;
            } else if (modifyClientInfoStatus == ERROR_RESEND || modifyClientInfoStatus == NONCE_HAS_USED) {
                char responseBuffer[sizeof(NetworkHeadStruct_t)];
                NetworkHeadStruct_t responseHead;
                responseHead.clientID = netHead.clientID;
                responseHead.dataSize = 0;
                responseHead.messageType = modifyClientInfoStatus;
                int sendSize = sizeof(NetworkHeadStruct_t);
                memcpy(responseBuffer, &responseHead, sizeof(NetworkHeadStruct_t));
                keySecurityChannel_->send(connection, responseBuffer, sendSize);
            } else if (modifyClientInfoStatus == -1) {
                cerr << "KeyServer : error init client messages, ecall not correct" << endl;
                return;
            }
        } else {
            cerr << "KeyServer : error recv client init messages" << endl;
            return;
        }
    }
#if SYSTEM_BREAK_DOWN == 1
    gettimeofday(&timeend, 0);
    diff = 1000000 * (timeend.tv_sec - timestart.tv_sec) + timeend.tv_usec - timestart.tv_usec;
    second = diff / 1000000.0;
    cout << "KeyServer : setup client init messages time = " << second << " s" << endl;
#endif
    //done
    while (true) {
        u_char hash[sizeof(NetworkHeadStruct_t) + config.getKeyBatchSize() * CHUNK_HASH_SIZE + 32];
        if (!keySecurityChannel_->recv(connection, (char*)hash, recvSize)) {

            multiThreadCountMutex_.lock();
            clientThreadCount_--;
            offlineGenerateFlag_ = true;
#if SYSTEM_BREAK_DOWN == 1
            cout << "KeyServer : total key generation time = " << keyGenTime << " s" << endl;
            cout << "KeyServer : total key generation number = " << currentThreadkeyGenerationNumber << endl;
            cerr << "keyServer : Thread exit due to client disconnect， current client counter = " << clientThreadCount_ << endl;
#endif
            multiThreadCountMutex_.unlock();
            return;
        }
        memcpy(&netHead, hash, sizeof(NetworkHeadStruct_t));
        int recvNumber = netHead.dataSize;
#if SYSTEM_DEBUG_FLAG == 1
        cout << "KeyServer : recv hash number = " << recvNumber << endl;
#endif
        u_char key[netHead.dataSize * CHUNK_HASH_SIZE + 32];
#if SYSTEM_BREAK_DOWN == 1
        gettimeofday(&timestart, 0);
#endif
        client->request(hash + sizeof(NetworkHeadStruct_t), netHead.dataSize * CHUNK_HASH_SIZE + 32, key, netHead.dataSize * CHUNK_HASH_SIZE + 32, netHead.clientID);
#if SYSTEM_BREAK_DOWN == 1
        gettimeofday(&timeend, 0);
        diff = 1000000 * (timeend.tv_sec - timestart.tv_sec) + timeend.tv_usec - timestart.tv_usec;
        second = diff / 1000000.0;
        keyGenTime += second;
#endif
#if SYSTEM_DEBUG_FLAG == 1
        cout << "KeyServer : generate key done for hash number = " << recvNumber << endl;
#endif
        multiThreadMutex_.lock();
        keyGenerateCount_ += recvNumber;
        multiThreadMutex_.unlock();
        currentThreadkeyGenerationNumber += recvNumber;
        if (!keySecurityChannel_->send(connection, (char*)key, recvNumber * CHUNK_ENCRYPT_KEY_SIZE + 32)) {
            cerr << "KeyServer : error send back chunk key to client" << endl;
            multiThreadCountMutex_.lock();
            clientThreadCount_--;
#if SYSTEM_BREAK_DOWN == 1
            cout << "KeyServer : total key generation time = " << keyGenTime << " s" << endl;
            cout << "KeyServer : total key generation number = " << currentThreadkeyGenerationNumber << endl;
            cerr << "keyServer : Thread exit due to client disconnect， current client counter = " << clientThreadCount_ << endl;
#endif
            multiThreadCountMutex_.unlock();
            return;
        }
#if SYSTEM_DEBUG_FLAG == 1
        else {
            cout << "KeyServer : send key to client " << netHead.clientID << " done for hash number = " << recvNumber << endl;
        }
#endif
    }
}

#endif
