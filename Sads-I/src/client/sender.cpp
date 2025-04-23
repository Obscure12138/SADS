#include "sender.hpp"
#include <sys/time.h>

extern Configure config;

struct timeval timestartSender;
struct timeval timeendSender;
struct timeval timestartSenderRun;
struct timeval timeendSenderRun;
struct timeval timestartSenderRecipe;
struct timeval timeendSenderRecipe;

void PRINT_BYTE_ARRAY_SENDER(FILE* file, void* mem, uint32_t len)
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

Sender::Sender()
{
    inputMQ_ = new messageQueue<Data_t>;
    dataSecurityChannel_ = new ssl(config.getStorageServerIP(), config.getStorageServerPort(), CLIENTSIDE);
    powSecurityChannel_ = new ssl(config.getStorageServerIP(), config.getPOWServerPort(), CLIENTSIDE);
    sslConnectionData_ = dataSecurityChannel_->sslConnect().second;
    sslConnectionPow_ = powSecurityChannel_->sslConnect().second;
    cryptoObj_ = new CryptoPrimitive();
    clientID_ = config.getClientID();
}

Sender::~Sender()
{
    delete dataSecurityChannel_;
    delete powSecurityChannel_;
    delete cryptoObj_;
    inputMQ_->~messageQueue();
    delete inputMQ_;
}

bool Sender::sendRecipe(Recipe_t request, RecipeList_t recipeList, int& status)
{
    int totalRecipeNumber = recipeList.size();
    int totalRecipeSize = totalRecipeNumber * sizeof(RecipeEntry_t) + sizeof(Recipe_t);
    u_char* recipeBuffer = (u_char*)malloc(sizeof(u_char) * totalRecipeNumber * sizeof(RecipeEntry_t));
    for (int i = 0; i < totalRecipeNumber; i++) {
        memcpy(recipeBuffer + i * sizeof(RecipeEntry_t), &recipeList[i], sizeof(RecipeEntry_t));
    }

    NetworkHeadStruct_t requestBody;
    requestBody.clientID = clientID_;
    requestBody.messageType = CLIENT_UPLOAD_ENCRYPTED_RECIPE;
    int sendSize = sizeof(NetworkHeadStruct_t);
    requestBody.dataSize = totalRecipeSize;
    char* requestBufferFirst = (char*)malloc(sizeof(char) * sendSize);
    memcpy(requestBufferFirst, &requestBody, sizeof(NetworkHeadStruct_t));
    if (!dataSecurityChannel_->send(sslConnectionData_, requestBufferFirst, sendSize)) {
        free(recipeBuffer);
        free(requestBufferFirst);
        cerr << "Sender : error sending file resipces size, peer may close" << endl;
        return false;
    } else {
        free(requestBufferFirst);
        sendSize = sizeof(NetworkHeadStruct_t) + totalRecipeSize;
        requestBody.dataSize = totalRecipeSize;
        char* requestBuffer = (char*)malloc(sizeof(char) * sendSize);
        memcpy(requestBuffer, &requestBody, sizeof(NetworkHeadStruct_t));
        memcpy(requestBuffer + sizeof(NetworkHeadStruct_t), &request, sizeof(Recipe_t));
        cryptoObj_->encryptWithKey(recipeBuffer, totalRecipeNumber * sizeof(RecipeEntry_t), cryptoObj_->chunkKeyEncryptionKey_, (u_char*)requestBuffer + sizeof(NetworkHeadStruct_t) + sizeof(Recipe_t));
        if (!dataSecurityChannel_->send(sslConnectionData_, requestBuffer, sendSize)) {
            free(recipeBuffer);
            free(requestBuffer);
            cerr << "Sender : error sending file resipces, peer may close" << endl;
            return false;
        } else {
            free(recipeBuffer);
            free(requestBuffer);
            return true;
        }
    }
}

bool Sender::sendChunkList(char* requestBufferIn, int sendBufferSize, int sendChunkNumber, int& status)
{
    NetworkHeadStruct_t requestBody;
    requestBody.clientID = clientID_;
    requestBody.messageType = CLIENT_UPLOAD_CHUNK;
    int sendSize = sizeof(NetworkHeadStruct_t) + sizeof(int) + sendBufferSize;
    memcpy(requestBufferIn + sizeof(NetworkHeadStruct_t), &sendChunkNumber, sizeof(int));
    requestBody.dataSize = sendBufferSize + sizeof(int);
    memcpy(requestBufferIn, &requestBody, sizeof(NetworkHeadStruct_t));
    if (!dataSecurityChannel_->send(sslConnectionData_, requestBufferIn, sendSize)) {
        cerr << "Sender : error sending chunk list, peer may close" << endl;
        return false;
    } else {
        return true;
    }
}

bool Sender::sendLogInMessage(int loginType)
{
    NetworkHeadStruct_t requestBody;
    requestBody.clientID = clientID_;
    requestBody.messageType = loginType;
    requestBody.dataSize = 0;
    int sendSize = sizeof(NetworkHeadStruct_t);
    char requestBuffer[sendSize];
    memcpy(requestBuffer, &requestBody, sizeof(NetworkHeadStruct_t));
    char respondBuffer[sizeof(NetworkHeadStruct_t)];
    int recvSize = 0;
    if (!this->sendDataPow(requestBuffer, sendSize, respondBuffer, recvSize)) {
        cerr << "Sender : peer closed, set log out error" << endl;
        return false;
    } else {
        return true;
    }
}

bool Sender::sendLogOutMessage()
{
    NetworkHeadStruct_t requestBody;
    requestBody.clientID = clientID_;
    requestBody.messageType = CLIENT_SET_LOGOUT;
    requestBody.dataSize = 0;
    int sendSize = sizeof(NetworkHeadStruct_t);
    char requestBuffer[sendSize];
    memcpy(requestBuffer, &requestBody, sizeof(NetworkHeadStruct_t));
    char respondBuffer[sizeof(NetworkHeadStruct_t)];
    int recvSize = 0;
    if (!this->sendDataPow(requestBuffer, sendSize, respondBuffer, recvSize)) {
        cerr << "Sender : peer closed, set log out error" << endl;
        return false;
    } else {
        return true;
    }
}


bool Sender::sendHashList(u_char* hashList, int requestNumber, u_char* respond, int& status)
{
    NetworkHeadStruct_t requestBody, respondBody;
    requestBody.messageType = HASH_LIST;
    requestBody.clientID = clientID_;
    respondBody.messageType = 0;
    respondBody.clientID = 0;
    respondBody.dataSize = 0;

    int sendSize = sizeof(NetworkHeadStruct_t) + requestNumber * CHUNK_HASH_SIZE;
    requestBody.dataSize = requestNumber * CHUNK_HASH_SIZE;
    char requestBuffer[sendSize];
    memcpy(requestBuffer, &requestBody, sizeof(NetworkHeadStruct_t));
    memcpy(requestBuffer + sizeof(NetworkHeadStruct_t), hashList, requestNumber * CHUNK_HASH_SIZE);
    char respondBuffer[sizeof(NetworkHeadStruct_t) + sizeof(bool) * requestNumber + sizeof(int)];
    int recvSize = 0;
    if (!this->sendDataPow(requestBuffer, sendSize, respondBuffer, recvSize)) {
        cerr << "Sender : send enclave signed hash to server & get back required chunk list error" << endl;
        return false;
    }
    memcpy(&respondBody, respondBuffer, sizeof(NetworkHeadStruct_t));
    status = respondBody.messageType;
    if (status == SUCCESS) {
        memcpy(respond, respondBuffer + sizeof(NetworkHeadStruct_t), sizeof(int) + sizeof(bool) * requestNumber);
        return true;
    } else {
        return false;
    }
}

bool Sender::sendDataPow(char* request, int requestSize, char* respond, int& respondSize)
{
    if (!powSecurityChannel_->send(sslConnectionPow_, request, requestSize)) {
        cerr << "Sender : send data error peer closed" << endl;
        return false;
    }
    if (!powSecurityChannel_->recv(sslConnectionPow_, respond, respondSize)) {
        cerr << "Sender : recv data error peer closed" << endl;
        return false;
    }
    return true;
}

bool Sender::sendEndFlag()
{
    NetworkHeadStruct_t requestBody, responseBody;
    requestBody.messageType = CLIENT_EXIT;
    requestBody.clientID = clientID_;
    int sendSize = sizeof(NetworkHeadStruct_t);
    int recvSize;
    requestBody.dataSize = 0;
    char requestBuffer[sendSize];
    char responseBuffer[sizeof(NetworkHeadStruct_t)];
    memcpy(requestBuffer, &requestBody, sizeof(NetworkHeadStruct_t));
    if (!powSecurityChannel_->send(sslConnectionPow_, requestBuffer, sendSize)) {
        cerr << "Sender : send end flag to pow server error peer closed" << endl;
        return false;
    }
    if (!powSecurityChannel_->recv(sslConnectionPow_, responseBuffer, recvSize)) {
        cerr << "Sender : recv end flag from pow server error peer closed" << endl;
        return false;
    } else {
        memcpy(&responseBody, responseBuffer, sizeof(NetworkHeadStruct_t));
        if (responseBody.messageType == SERVER_JOB_DONE_EXIT_PERMIT) {
            if (!dataSecurityChannel_->send(sslConnectionData_, requestBuffer, sendSize)) {
                cerr << "Sender : send end flag to data server error peer closed" << endl;
                return false;
            }
            if (!dataSecurityChannel_->recv(sslConnectionData_, responseBuffer, recvSize)) {
                cerr << "Sender : recv end flag from data server error peer closed" << endl;
                return false;
            } else {
                memcpy(&responseBody, responseBuffer, sizeof(NetworkHeadStruct_t));
                if (responseBody.messageType == SERVER_JOB_DONE_EXIT_PERMIT) {
                    return true;
                } else {
                    return false;
                }
            }
        } else {
            return false;
        }
    }

    return true;
}

void Sender::run()
{
    Data_t tempChunk;
    RecipeList_t recipeList;
    Recipe_t fileRecipe;
    int sendBatchSize = config.getSendChunkBatchSize();
    int status;
    char* sendChunkBatchBuffer = (char*)malloc(sizeof(NetworkHeadStruct_t) + sizeof(int) + sizeof(char) * sendBatchSize * (CHUNK_HASH_SIZE + MAX_CHUNK_SIZE + sizeof(int)));
    bool jobDoneFlag = false;
    int currentChunkNumber = 0;
    int currentSendRecipeNumber = 0;
    int currentSendChunkBatchBufferSize = sizeof(NetworkHeadStruct_t) + sizeof(int);
#if SYSTEM_BREAK_DOWN == 1
#endif
    double totalSendChunkTime = 0;
    double totalChunkAssembleTime = 0;
    double totalSendRecipeTime = 0;
    double totalRecipeAssembleTime = 0;
    double totalReadMessageQueueTime = 0;
    double totalSenderRunTime = 0;
    long diff;
    double second;
#if SYSTEM_BREAK_DOWN == 1
#endif
    gettimeofday(&timestartSenderRun, NULL);
    while (!jobDoneFlag) {
        if (inputMQ_->done_ && inputMQ_->isEmpty()) {
            jobDoneFlag = true;
        }
#if SYSTEM_BREAK_DOWN == 1
#endif
        gettimeofday(&timestartSender, NULL);
        bool extractChunkStatus = extractMQ(tempChunk);
#if SYSTEM_BREAK_DOWN == 1
#endif
        gettimeofday(&timeendSender, NULL);
        diff = 1000000 * (timeendSender.tv_sec - timestartSender.tv_sec) + timeendSender.tv_usec - timestartSender.tv_usec;
        second = diff / 1000000.0;
        totalReadMessageQueueTime += second;
        if (extractChunkStatus) {
            if (tempChunk.dataType == DATA_TYPE_RECIPE) {
#if SYSTEM_DEBUG_FLAG == 1
                cout << "Sender : get file recipe head, file size = " << tempChunk.recipe.fileRecipeHead.fileSize << " file chunk number = " << tempChunk.recipe.fileRecipeHead.totalChunkNumber << endl;
                PRINT_BYTE_ARRAY_SENDER(stderr, tempChunk.recipe.fileRecipeHead.fileNameHash, FILE_NAME_HASH_SIZE);
#endif
                memcpy(&fileRecipe, &tempChunk.recipe, sizeof(Recipe_t));
                continue;
            } else {
                if (tempChunk.chunk.type == CHUNK_TYPE_NEED_UPLOAD) {
#if SYSTEM_BREAK_DOWN == 1
#endif
                    gettimeofday(&timestartSender, NULL);
                    memcpy(sendChunkBatchBuffer + currentSendChunkBatchBufferSize, tempChunk.chunk.chunkHash, CHUNK_HASH_SIZE);
                    currentSendChunkBatchBufferSize += CHUNK_HASH_SIZE;
                    memcpy(sendChunkBatchBuffer + currentSendChunkBatchBufferSize, &tempChunk.chunk.logicDataSize, sizeof(int));
                    currentSendChunkBatchBufferSize += sizeof(int);
                    memcpy(sendChunkBatchBuffer + currentSendChunkBatchBufferSize, tempChunk.chunk.logicData, tempChunk.chunk.logicDataSize);
                    currentSendChunkBatchBufferSize += tempChunk.chunk.logicDataSize;
                    currentChunkNumber++;
                    // cout << "Sender : Chunk ID = " << tempChunk.chunk.ID << " size = " << tempChunk.chunk.logicDataSize << endl;
#if SYSTEM_BREAK_DOWN == 1
#endif
                    gettimeofday(&timeendSender, NULL);
                    diff = 1000000 * (timeendSender.tv_sec - timestartSender.tv_sec) + timeendSender.tv_usec - timestartSender.tv_usec;
                    second = diff / 1000000.0;
                    totalChunkAssembleTime += second;
                }
#if SYSTEM_BREAK_DOWN == 1
#endif
                gettimeofday(&timestartSender, NULL);
                RecipeEntry_t newRecipeEntry;
                newRecipeEntry.chunkID = tempChunk.chunk.ID;
                newRecipeEntry.chunkSize = tempChunk.chunk.logicDataSize;
                memcpy(newRecipeEntry.chunkHash, tempChunk.chunk.chunkHash, CHUNK_HASH_SIZE);
                memcpy(newRecipeEntry.chunkKey, tempChunk.chunk.encryptKey, CHUNK_ENCRYPT_KEY_SIZE);
                recipeList.push_back(newRecipeEntry);
                currentSendRecipeNumber++;
#if SYSTEM_BREAK_DOWN == 1
#endif
                gettimeofday(&timeendSender, NULL);
                diff = 1000000 * (timeendSender.tv_sec - timestartSender.tv_sec) + timeendSender.tv_usec - timestartSender.tv_usec;
                second = diff / 1000000.0;
                totalRecipeAssembleTime += second;
            }
        }
        if (currentChunkNumber == sendBatchSize || jobDoneFlag) {
            // cout << "Sender : run -> start send " << setbase(10) << currentChunkNumber << " chunks to server, size = " << setbase(10) << currentSendChunkBatchBufferSize << endl;
#if SYSTEM_BREAK_DOWN == 1
#endif
            gettimeofday(&timestartSender, NULL);
            if (this->sendChunkList(sendChunkBatchBuffer, currentSendChunkBatchBufferSize, currentChunkNumber, status)) {
                // cout << "Sender : sent " << setbase(10) << currentChunkNumber << " chunk" << endl;
                currentSendChunkBatchBufferSize = sizeof(NetworkHeadStruct_t) + sizeof(int);
                memset(sendChunkBatchBuffer, 0, sizeof(NetworkHeadStruct_t) + sizeof(int) + sizeof(char) * sendBatchSize * (CHUNK_HASH_SIZE + MAX_CHUNK_SIZE + sizeof(int)));
                currentChunkNumber = 0;
#if SYSTEM_BREAK_DOWN == 1
#endif
                gettimeofday(&timeendSender, NULL);
                diff = 1000000 * (timeendSender.tv_sec - timestartSender.tv_sec) + timeendSender.tv_usec - timestartSender.tv_usec;
                second = diff / 1000000.0;
                totalSendChunkTime += second;
            } else {
                cerr << "Sender : send " << setbase(10) << currentChunkNumber << " chunk error" << endl;
#if SYSTEM_BREAK_DOWN == 1
#endif
                gettimeofday(&timeendSender, NULL);
                diff = 1000000 * (timeendSender.tv_sec - timestartSender.tv_sec) + timeendSender.tv_usec - timestartSender.tv_usec;
                second = diff / 1000000.0;
                totalSendChunkTime += second;
                break;
            }
        }
    }
#if SYSTEM_BREAK_DOWN == 1
    cout << "Sender : assemble chunk list time = " << totalChunkAssembleTime << " s" << endl;
    cout << "Sender : chunk upload and storage service time = " << totalSendChunkTime << " s" << endl;
#endif
#if SYSTEM_BREAK_DOWN == 1
    gettimeofday(&timestartSender, NULL);
#endif
#if SYSTEM_DEBUG_FLAG == 1
    cout << "Sender : start send file recipes" << endl;
#endif
    if (!this->sendRecipe(fileRecipe, recipeList, status)) {
        cerr << "Sender : send recipe list error, upload fail " << endl;
        free(sendChunkBatchBuffer);
        bool serverJobDoneFlag = sendEndFlag();
        if (serverJobDoneFlag) {
            return;
        } else {
            cerr << "Sender : server job done flag error, server may shutdown, upload may faild" << endl;
            return;
        }
    }
#if SYSTEM_BREAK_DOWN == 1
#endif
    gettimeofday(&timeendSenderRun, NULL);
    diff = 1000000 * (timeendSenderRun.tv_sec - timestartSenderRun.tv_sec) + timeendSenderRun.tv_usec - timestartSenderRun.tv_usec;
    second = diff / 1000000.0;
    totalSenderRunTime += second;
    gettimeofday(&timeendSender, NULL);
    diff = 1000000 * (timeendSender.tv_sec - timestartSender.tv_sec) + timeendSender.tv_usec - timestartSender.tv_usec;
    second = diff / 1000000.0;
    totalSendRecipeTime += second;
#if SYSTEM_BREAK_DOWN == 1
    cout << "Sender : assemble recipe list time = " << totalRecipeAssembleTime << " s" << endl;
    cout << "Sender : send recipe list time = " << totalSendRecipeTime << " s" << endl;
    cout << "Sender : total thread work time = " << totalSenderRunTime - totalReadMessageQueueTime << " s" << endl;
#endif
    cout << "Sender : total sending work time = " << totalRecipeAssembleTime + totalSendRecipeTime + totalChunkAssembleTime + totalSendChunkTime << " s" << endl;
    free(sendChunkBatchBuffer);
    bool serverJobDoneFlag = sendEndFlag();
    if (serverJobDoneFlag) {
        return;
    } else {
        cerr << "Sender : server job done flag error, server may shutdown, upload may faild" << endl;
        return;
    }
}

bool Sender::insertMQ(Data_t& newChunk)
{
    return inputMQ_->push(newChunk);
}

bool Sender::extractMQ(Data_t& newChunk)
{
    return inputMQ_->pop(newChunk);
}

bool Sender::editJobDoneFlag()
{
    inputMQ_->done_ = true;
    if (inputMQ_->done_) {
        return true;
    } else {
        return false;
    }
}
