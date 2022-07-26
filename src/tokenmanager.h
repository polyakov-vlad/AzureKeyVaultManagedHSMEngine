#ifndef TOKENMANAGER_H
#define TOKENMANAGER_H

#include "pthread.h"
#include "time.h"
#include "pch.h"
#include "log.h"
#include "unistd.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct Token
{
    char* accesstoken;
    time_t acquired;
    time_t expiration;
    size_t size;
};

/*
* Array that contains tokens for both the AKV [0] and the MHSM [1].
*/
struct Token tokens[2];

/**
 * @brief Refreshes and returns the token of the specified type.
 * 
 * @param type String that has which type of access token to recieve (vault or managedHsm).
 */
void refresh(char* type);

/**
 * @brief Initializes the tokens so that they both have access values on startup.
 * 
 * @param token_access_mutex The mutex that 
 */
void init_tokens(pthread_mutex_t token_access_mutex);

/**
 * @brief Updates the token if needed. This function will be ran via thread.
 * 
 * @param arg void* argument for thread creation
 * @return void* return for thread creation
 */
void* update_token(void * arg);

/**
 * @brief Get the access token value based on the type passed in. 
 * 
 * @param type String that has which type of access token to recieve (vault or managedHsm).
 * @return Specified token
 */
struct Token get_token(char* type);

#endif /* TOKENMANAGER_H */