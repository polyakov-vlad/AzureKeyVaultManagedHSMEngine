#ifndef TOKENMANAGER_H
#define TOKENMANAGER_H
#define NUMBEROFTOKENS 2

#include "pthread.h"
#include "time.h"
#include "pch.h"
#include "log.h"
#include "unistd.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*
* Struct that contains the accesstoken, acquired time, expiration time, and size of accesstoken
*/
struct Token
{
    char* accesstoken;
    time_t acquired;
    time_t expiration;
    size_t size;
};

struct Token tokens[NUMBEROFTOKENS];

/**
 * @brief Refreshes and returns the token of the specified type.
 * 
 * @param type String that has which type of access token to recieve (vault or managedHsm).
 */
void refresh(char* type);

/**
 * @brief Initializes the tokens so that they both have access values on startup.
 * 
 * @param token_access_mutex mutex to block access/write when updating 
 */
void init_tokens(pthread_mutex_t token_access_mutex);

/**
 * @brief Updates the token if needed. This function will be ran via thread.
 * 
 * @param arg void* argument for thread creation
 * @return void* return for thread creation
 */
void* update_token(void* arg);

/**
 * @brief Get the access token value based on the type passed in. 
 * 
 * @param type String that has which type of access token to recieve (vault or managedHsm).
 * @return Specified token
 */
struct Token get_token(char* type);

#endif /* TOKENMANAGER_H */