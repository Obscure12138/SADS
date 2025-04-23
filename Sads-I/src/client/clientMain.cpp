#include "powClient.hpp"
#include "chunker.hpp"
#include "configure.hpp"
//#include "encoder.hpp"
#include "fingerprinter.hpp"
#include "keyClient.hpp"
#include "characterer.hpp"
//#include "recvDecode.hpp"
//#include "retriever.hpp"
#include "sender.hpp"
#include "sys/time.h"
#include <bits/stdc++.h>
#include <boost/thread/thread.hpp>
#include <signal.h>
#include <dirent.h>
#include <fstream>

using namespace std;

Configure config("config.json");
Chunker* chunkerObj;
Fingerprinter* fingerprinterObj;
KeyClient* keyClientObj;
//Encoder* encoderObj;
powClient* powClientObj;
Sender* senderObj;
Characterer* charactererObj;
//RecvDecode* recvDecodeObj;
//Retriever* retrieverObj;

struct timeval timestart;
struct timeval timeend;
struct timeval timestartBreakDown;
struct timeval timeendBreakDown;

void PRINT_BYTE_ARRAY_CLIENT_MAIN(
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

void CTRLC(int s)
{
    cerr << "Client exit with keyboard interrupt" << endl;
    if (chunkerObj != nullptr) {
        delete chunkerObj;
    }
    if (fingerprinterObj != nullptr) {
        delete fingerprinterObj;
    }
    if (keyClientObj != nullptr) {
        delete keyClientObj;
    }
    // if (encoderObj != nullptr) {
    //     delete encoderObj;
    // }
    if (powClientObj != nullptr) {
        delete powClientObj;
    }
    if (senderObj != nullptr) {
        delete senderObj;
    }
    if(charactererObj != nullptr){
        delete charactererObj;
    }
    // if (recvDecodeObj != nullptr) {
    //     delete recvDecodeObj;
    // }
    // if (retrieverObj != nullptr) {
    //     delete retrieverObj;
    // }
    exit(0);
}

void usage()
{
    cout << "[client --setup ] for setup system only, following input for system operation" << endl;
    cout << "[client -s filename] for send file" << endl;
    cout << "[client -r filename] for receive file" << endl;
    cout << "[client -k ThreadNumber keyNumber] for multi-thread key generate simluate" << endl;
}

int main(int argv, char* argc[])
{
    struct sigaction sa;
    sa.sa_handler = SIG_IGN;
    sigaction(SIGPIPE, &sa, 0);

    sa.sa_handler = CTRLC;
    sigaction(SIGKILL, &sa, 0);
    sigaction(SIGINT, &sa, 0);

    long diff;
    double second;

    if (argv != 2 && argv != 3 && argv != 4 && argv != 5) {
        usage();
        return 0;
    }
//     if (strcmp("-r", argc[1]) == 0) {
//         vector<boost::thread*> thList;
//         boost::thread* th;
//         boost::thread::attributes attrs;
//         attrs.set_stack_size(200 * 1024 * 1024);
//         gettimeofday(&timestart, NULL);
//         string fileName(argc[2]);
//         recvDecodeObj = new RecvDecode(fileName);
//         retrieverObj = new Retriever(fileName, recvDecodeObj);
//         gettimeofday(&timeend, NULL);
//         diff = 1000000 * (timeend.tv_sec - timestart.tv_sec) + timeend.tv_usec - timestart.tv_usec;
//         second = diff / 1000000.0;
//         cout << "System : Init download time is " << second << " s" << endl;

//         gettimeofday(&timestart, NULL);
//         // start recv data & decrypt thread
//         th = new boost::thread(attrs, boost::bind(&RecvDecode::run, recvDecodeObj));
//         thList.push_back(th);
//         // start write file thread
//         th = new boost::thread(attrs, boost::bind(&Retriever::run, retrieverObj));
//         thList.push_back(th);

//         for (auto it : thList) {
//             it->join();
//         }

//         gettimeofday(&timeend, NULL);
//         diff = 1000000 * (timeend.tv_sec - timestart.tv_sec) + timeend.tv_usec - timestart.tv_usec;
//         second = diff / 1000000.0;

//         delete recvDecodeObj;
//         delete retrieverObj;

//         cout << "System : total work time is " << second << " s" << endl;
// #if MULTI_CLIENT_UPLOAD_TEST == 1
//         cout << "System : start work time is " << timestart.tv_sec << " s, " << timestart.tv_usec << " us" << endl;
//         cout << "System : finish work time is " << timeend.tv_sec << " s, " << timeend.tv_usec << " us" << endl;
// #endif
//         cout << endl;
//         return 0;
//          }
 if (strcmp("-k", argc[1]) == 0) {
        vector<boost::thread*> thList;
        boost::thread* th;
        boost::thread::attributes attrs;
        attrs.set_stack_size(10 * 1024 * 1024);
        gettimeofday(&timestart, NULL);
        int keyGenNumber = atoi(argc[2]);
#if SYSTEM_BREAK_DOWN == 1
        gettimeofday(&timestartBreakDown, NULL);
#endif

        keyClientObj = new KeyClient(keyGenNumber);

        gettimeofday(&timeend, NULL);
        diff = 1000000 * (timeend.tv_sec - timestart.tv_sec) + timeend.tv_usec - timestart.tv_usec;
        second = diff / 1000000.0;
        cout << "System : Init key generate simulator time is " << second << " s" << endl;

        gettimeofday(&timestart, NULL);
        for (int i = 0; i < 1; i++) {
            th = new boost::thread(attrs, boost::bind(&KeyClient::runKeyGenSimulator, keyClientObj));
            thList.push_back(th);
        }
        for (auto it : thList) {
            it->join();
        }
        gettimeofday(&timeend, NULL);
        diff = 1000000 * (timeend.tv_sec - timestart.tv_sec) + timeend.tv_usec - timestart.tv_usec;
        second = diff / 1000000.0;
        //keyClientObj->outputKeyGenSimulatorRunningTime();
        delete keyClientObj;

        cout << "System : total work time is " << second << " s" << endl;
#if MULTI_CLIENT_UPLOAD_TEST == 1
        cout << "System : start work time is " << timestart.tv_sec << " s, " << timestart.tv_usec << " us" << endl;
        cout << "System : finish work time is " << timeend.tv_sec << " s, " << timeend.tv_usec << " us" << endl;
#endif
        cout << endl;
        return 0;

    } 
if (strcmp("-s", argc[1]) == 0) {
        vector<boost::thread*> thList;
        boost::thread* th;
        boost::thread::attributes attrs;
        attrs.set_stack_size(200 * 1024 * 1024);
       	ofstream out("result",ios::out|ios::app);

        gettimeofday(&timestart, NULL);

        senderObj = new Sender();
        powClientObj = new powClient(senderObj);

        keyClientObj = new KeyClient(powClientObj);
        charactererObj = new Characterer(keyClientObj);
        fingerprinterObj = new Fingerprinter(charactererObj);

        string inputFile(argc[2]);
        chunkerObj = new Chunker(inputFile, fingerprinterObj);

        gettimeofday(&timeend, NULL);
        diff = 1000000 * (timeend.tv_sec - timestart.tv_sec) + timeend.tv_usec - timestart.tv_usec;
        second = diff / 1000000.0;
        cout << "System : Init upload time is " << second << " s" << endl;

        gettimeofday(&timestart, NULL);
        //start chunking thread
        th = new boost::thread(attrs, boost::bind(&Chunker::chunking, chunkerObj));
        thList.push_back(th);

        //start fingerprinting thread
        th = new boost::thread(attrs, boost::bind(&Fingerprinter::run, fingerprinterObj));
        thList.push_back(th);

        //start featuring thread
        th = new boost::thread(attrs, boost::bind(&Characterer::SimilarityHashRun, charactererObj));
        thList.push_back(th);

        //start key client thread
        th = new boost::thread(attrs, boost::bind(&KeyClient::run, keyClientObj));
        thList.push_back(th);

        //start pow thread
        th = new boost::thread(attrs, boost::bind(&powClient::run, powClientObj));
        thList.push_back(th);

        //start sender thread
        th = new boost::thread(attrs, boost::bind(&Sender::run, senderObj));
        thList.push_back(th);

        for (auto it : thList) {
            it->join();
        }

        gettimeofday(&timeend, NULL);
        diff = 1000000 * (timeend.tv_sec - timestart.tv_sec) + timeend.tv_usec - timestart.tv_usec;
        second = diff / 1000000.0;
        delete senderObj;
        delete powClientObj;
        delete keyClientObj;
        delete charactererObj;
        delete fingerprinterObj;
        delete chunkerObj;

        cout << "System : upload total work time is " << second << " s" << endl;

        cout << endl;

        out<<second<<endl;
        return 0;

    } else {
        usage();
        return 0;
    }
}
