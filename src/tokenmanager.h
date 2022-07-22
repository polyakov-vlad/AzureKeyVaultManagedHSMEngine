#ifndef TOKENMANAGER_H
#define TOKENMANAGER_H

#include "time.h"

struct TokenManager
{
    char* accesstoken;
    time_t expiration;
    size_t size;
};

#endif /* TOKENMANAGER_H */