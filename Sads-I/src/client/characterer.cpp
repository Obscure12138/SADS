#include "characterer.hpp"
#include <bitset>
#include <fstream>
#include <vector>

#define featureCount 4

struct similarityInfo
{
    set<string> hash_set;
    int chunkSize;
    int latestUser;
    int userCount;
    int sameCount;
    int sameUserCount;
    vector<Data_t> chunkData;
};

int MinEditDistance(Data_t block1, Data_t block2)
{
    vector<vector<int>> dp(block1.chunk.logicDataSize + 1, vector<int>(block2.chunk.logicDataSize + 1,0));
    for (int i=0 ; i<block1.chunk.logicDataSize + 1 ; i++)
    {
        dp[i][0] =  i;
    }
    for (int i=0;i<block2.chunk.logicDataSize + 1 ; i++ )
    {
        dp[0][i] =  i;
    }
    for(int i=1;i<block1.chunk.logicDataSize + 1 ; i++)
    {
        for (int j=1;j<block2.chunk.logicDataSize + 1 ; j++ )
        {
            if(block1.chunk.logicData[i-1] == block2.chunk.logicData[j-1])
            {
                dp[i][j] = dp[i-1][j-1];
            }
            else{
                dp[i][j] = min({dp[i - 1][j - 1], dp[i - 1][j], dp[i][j - 1]}) + 1;
            }
        }
    }
    return dp[block1.chunk.logicDataSize][block2.chunk.logicDataSize];
}

bitset<256> BitsfromByteArray(const unsigned char* bytes)
{
	bitset<256> bits;
	for (int i = 0; i < 64; i++)
	{
		if ((bytes[i / 8] & (1 << (7 - i % 8))) > 0)
		{
			bits.set(i);
		}
	}
	return bits;
}

void BitstoByteArray(bitset<256>& bits, unsigned char* bytes)
{
	for (int i = 0; i < 256; i++)
	{
		if (bits.test(i))
		{
			bytes[i / 8] |= 1 << (7 - i % 8);
		}
	}
}

Characterer::Characterer(KeyClient* keyClientObjTemp)
{
    keyClientObj_ = keyClientObjTemp;
    cryptoObj_ = new CryptoPrimitive();
    inputMQ_ = new messageQueue<Data_t>;

    slidingWinSize_ = 64;
    polyBase_ = 257; /*a prime larger than 255, the max value of "unsigned char"*/
    polyMOD_ = UINT64_MAX; /*polyMOD_ - 1 = 0x7fffff: use the last 23 bits of a polynomial as its hash*/
    /*initialize the lookup table for accelerating the power calculation in rolling hash*/
    powerLUT_ = (uint64_t*)malloc(sizeof(uint64_t) * slidingWinSize_);
    memset(powerLUT_, 0, sizeof(uint64_t) * slidingWinSize_);
    /*powerLUT_[i] = power(polyBase_, i) mod polyMOD_*/
    powerLUT_[0] = 1;
    for (int i = 1; i < slidingWinSize_; i++) {
        /*powerLUT_[i] = (powerLUT_[i-1] * polyBase_) mod polyMOD_*/
        powerLUT_[i] = (powerLUT_[i - 1] * polyBase_) & polyMOD_;
    }
    /*initialize the lookup table for accelerating the byte remove in rolling hash*/
    removeLUT_ = (uint64_t*)malloc(sizeof(uint64_t) * 256); /*256 for unsigned char*/
    memset(removeLUT_, 0, sizeof(uint64_t) * 256);
    for (int i = 0; i < 256; i++) {
        /*removeLUT_[i] = (- i * powerLUT_[_slidingWinSize-1]) mod polyMOD_*/
        removeLUT_[i] = (i * powerLUT_[slidingWinSize_ - 1]) & polyMOD_;
        if (removeLUT_[i] != 0) {

            removeLUT_[i] = (polyMOD_ - removeLUT_[i] + 1) & polyMOD_;
        }
        /*note: % is a remainder (rather than modulus) operator*/
        /*      if a < 0,  -polyMOD_ < a % polyMOD_ <= 0       */
    }
}

Characterer::~Characterer()
{
    if (powerLUT_ != NULL) {
        delete powerLUT_;
    }
    if (removeLUT_ != NULL) {
        delete removeLUT_;
    }
    if (cryptoObj_ != NULL) {
        delete cryptoObj_;
    }
    if(inputMQ_ != NULL)
    {
        inputMQ_->~messageQueue();
        delete inputMQ_;
    }
}

void Characterer::MinhashRun()
{
    double second;
    long diff;
    double characterTime = 0;
    struct timeval timestart;
    struct timeval timeend;
    bool JobDoneFlag = false;
    while(true)
    {
        Data_t tempChunk;
        if (inputMQ_->done_ && inputMQ_->isEmpty()) {
            JobDoneFlag = true;
        }
        if(extractMQ(tempChunk))
        {
            if(tempChunk.dataType == DATA_TYPE_RECIPE)
            {
                keyClientObj_->insertMQ(tempChunk);
                continue;
            }
            else{
                gettimeofday(&timestart,NULL);
                uint32_t winFp = 0;
                uint32_t feature = 0xFFFFFFFF;
                for(int i=0;i<tempChunk.chunk.logicDataSize;i++)
                {
                    if(i < slidingWinSize_)
                    {
                        winFp = winFp + (tempChunk.chunk.logicData[i] * powerLUT_[slidingWinSize_ - i -1]) & polyMOD_;
                        continue;
                    }
                    winFp &= (polyMOD_);

                    unsigned short int v = tempChunk.chunk.logicData[i - slidingWinSize_];
                    winFp = ((winFp + removeLUT_[v]) * polyBase_ + tempChunk.chunk.logicData[i]) & polyMOD_; //remove queue front and add queue tail

                    if(winFp < feature)
                    {
                        feature = winFp;
                    }
                }
                if(!cryptoObj_->generateHash((u_char*)to_string(feature).c_str(),to_string(feature).size(),tempChunk.chunk.feature))
                {
                    cout<<"generate chunk similarity error!"<<endl;
                    return ;
                }
                gettimeofday(&timeend,NULL);
                diff = 1000000 * (timeend.tv_sec - timestart.tv_sec) + timeend.tv_usec - timestart.tv_usec;
                second = diff / 1000000.0;
                characterTime += second;
                keyClientObj_->insertMQ(tempChunk);
            }
        }
        if(JobDoneFlag)
        {
            if(!keyClientObj_->editJobDoneFlag())
            {
                cout<<"Characterer : error to set job done flag for parse"<<endl;
            }
            cout<<"Character : total run time = "<<setbase(10)<<characterTime<<endl;
            break;
        }
    }
}

void Characterer::SimilarityHashRun()
{
    bool JobDoneFlag = false;
    double second;
    long diff;
    double extractTime = 0;
    struct timeval timestart;
    struct timeval timeend;

    uint64_t feature[16];
    uint64_t a[16]= { 3433, 3449, 3457, 3461, 3463, 3467, 3469, 3491, 3499, 3511, 3517, 3527, 3529, 3533, 3539, 3541 };
    uint64_t b[16]= { 3083, 3089, 3109, 3119, 3121, 3137, 3163, 3167, 3169, 3181, 3187, 3191, 3203, 3209, 3217, 3221 };

    u_char FeatureHash[CHUNK_HASH_SIZE];
    bitset<256> BitHash;

    while(true)
    {
        Data_t tempChunk;
        if (inputMQ_->done_ && inputMQ_->isEmpty()) {
            JobDoneFlag = true;
        }
        if(extractMQ(tempChunk))
        {
            if(tempChunk.dataType == DATA_TYPE_RECIPE)
            {
                keyClientObj_->insertMQ(tempChunk);
                continue;
            }
            else{
                gettimeofday(&timestart,NULL);

    	        int CountHash[256] = {0};
                uint64_t winFp = 0 , tmpFp = 0;
                for(int i=0;i<featureCount;i++)
                {
                    feature[i] = UINT64_MAX;
                }

                for(int i=0;i<tempChunk.chunk.logicDataSize;i++)
                {
                    if(i < slidingWinSize_)
                    {
                        winFp = winFp + (tempChunk.chunk.logicData[i] * powerLUT_[slidingWinSize_ - i -1]) & polyMOD_;
                        continue;
                    }
                    winFp &= (polyMOD_);

                    unsigned short int v = tempChunk.chunk.logicData[i - slidingWinSize_];
                    winFp = ((winFp + removeLUT_[v]) * polyBase_ + tempChunk.chunk.logicData[i]) & polyMOD_; //remove queue front and add queue tail
                    for(int i=0;i<featureCount;i++)
                    {
                        tmpFp = (a[i] * winFp + b[i]) & UINT64_MAX;
                        if(tmpFp < feature[i])
                        {
                            feature[i] = tmpFp;
                        }
                    }
                }
                for(int i=0;i<featureCount;i++)
                {
                    cryptoObj_->generateHash((u_char*)to_string(feature[i]).c_str(), to_string (feature[i]).size(),FeatureHash);
                    BitHash = BitsfromByteArray((const unsigned char*)FeatureHash);
                    for(int j=0;j<256;j++)
                    {
                        if(BitHash[j]==1)
                        {
                            CountHash[j]++;
                        }
                        else{
                            CountHash[j]--;
                        }
                    }
                }
                for(int i=0;i<256;i++)
                {
                    if(CountHash[i]>0)
                    {
                        BitHash[i] = 1;
                    }
                    else{
                        BitHash[i] = 0;
                    }
                }
                BitstoByteArray(BitHash,tempChunk.chunk.feature);
                gettimeofday(&timeend,NULL);
                diff = 1000000 * (timeend.tv_sec - timestart.tv_sec) + timeend.tv_usec - timestart.tv_usec;
                second = diff / 1000000.0;
                extractTime += second;
                keyClientObj_->insertMQ(tempChunk);
            }
        }
        if(JobDoneFlag)
        {
            if(!keyClientObj_->editJobDoneFlag())
            {
                cout<<"Characterer : error to set job done flag for parse"<<endl;
            }
            cout<<"Character : total run time = "<<setbase(10)<<extractTime<<endl;
            break;
        }
    }

}

bool Characterer::insertMQ(Data_t& newChunk)
{
    return inputMQ_->push(newChunk);
}

bool Characterer::extractMQ(Data_t& newChunk)
{
    return inputMQ_->pop(newChunk);
}

bool Characterer::editJobDoneFlag()
{
    inputMQ_->done_ = true;
    if (inputMQ_->done_) {
        return true;
    } else {
        return false;
    }
}

