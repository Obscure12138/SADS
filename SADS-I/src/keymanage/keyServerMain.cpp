#include "keyServer.hpp"
#include <signal.h>

Configure config("config.json");
keyServer* server;

struct timeval timestartKeyServerMain;
struct timeval timeendKeyServerMain;

void CTRLC(int s)
{
    cerr << "KeyManager exit with keyboard interrupt" << endl;
    delete server;
    exit(0);
}

int main()
{
    struct sigaction sa;
    sa.sa_handler = SIG_IGN;
    sigaction(SIGPIPE, &sa, 0);

    sa.sa_handler = CTRLC;
    sigaction(SIGKILL, &sa, 0);
    sigaction(SIGINT, &sa, 0);

    ssl* keySecurityChannelTemp = new ssl(config.getKeyServerIP(), config.getKeyServerPort(), SERVERSIDE);
    boost::thread* th;
    server = new keyServer(keySecurityChannelTemp);
    while (true) {
        SSL* sslConnection = keySecurityChannelTemp->sslListen().second;
        th = new boost::thread(boost::bind(&keyServer::runKeyGenerateThread, server, sslConnection));
        th->detach();
    }
    return 0;
}