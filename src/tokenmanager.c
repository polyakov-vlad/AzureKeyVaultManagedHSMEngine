#include "tokenmanager.h"
// #include <curl/curl.h>


/**
 * @brief Refreshes and returns the token of the specified type.
 * 
 * @param type String that has which type of access token to recieve (vault or managedHsm).
 */
void refresh(char* type){
    log_info("Initiated refresh for the %s...", type);
    CURL *curl_handle;
    CURLcode res;

    MemoryStruct at;
    MemoryStruct *accessToken;
    accessToken = &at;
    accessToken->memory = malloc(1);
    accessToken->size = 0;

    char *IDMSEnv = NULL;
    size_t requiredSize;
    IDMSEnv = getenv("IDENTITY_ENDPOINT");
    char idmsUrl[4 * 1024] = {0};

    if (IDMSEnv)
    {
        log_info( "Use overrided IDMS url : %s\n", IDMSEnv);
        strncat(idmsUrl, IDMSEnv, sizeof idmsUrl);
        strncat(idmsUrl, "?api-version=2018-02-01", sizeof idmsUrl);
    }
    else
    {
        strncat(idmsUrl, "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01", sizeof idmsUrl);
    }
    if (strcasecmp(type, "vault") == 0)
    {
        strncat(idmsUrl, "&resource=https://vault.azure.net", sizeof idmsUrl);
    }
    else if (strcasecmp(type, "managedHsm") == 0)
    {
        strncat(idmsUrl, "&resource=https://managedhsm.azure.net", sizeof idmsUrl);
    }

    log_info("before curl"); 
    curl_handle = curl_easy_init();
    curl_easy_setopt(curl_handle, CURLOPT_URL, idmsUrl);
    struct curl_slist *headers = NULL;
    headers = curl_slist_append(headers, "Content-Type: application/json");
    headers = curl_slist_append(headers, "Metadata: true");
    curl_easy_setopt(curl_handle, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl_handle, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
    curl_easy_setopt(curl_handle, CURLOPT_WRITEDATA, (void *)accessToken);
    curl_easy_setopt(curl_handle, CURLOPT_USERAGENT, "libcurl-agent/1.0");
    res = curl_easy_perform(curl_handle);
    curl_easy_cleanup(curl_handle);
    
    if (res != CURLE_OK)
    {
        log_error( "curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
        free(accessToken->memory);
        accessToken->memory = NULL;
        accessToken->size = 0;
        return;
    }

    struct json_object *parsed_json;
    struct json_object *atoken;
    struct json_object *expires_on;
    parsed_json = json_tokener_parse(accessToken->memory);
    if (!json_object_object_get_ex(parsed_json, "access_token", &atoken)) {
        log_error( "An access_token field was not found in the IDMS endpoint response. Is a managed identity available?\n");
        free(accessToken->memory);
        accessToken->memory = NULL;
        accessToken->size = 0;
        return;
    }

    if (!json_object_object_get_ex(parsed_json, "expires_on", &expires_on)) {
        log_error( "Failed to find the expiration time for this token\n");
        free(accessToken->memory);
        accessToken->memory = NULL;
        accessToken->size = 0;
        return;
    }

    time_t expiration_time;
    time_t now = time(NULL);
    const char *accessTokenStr = json_object_get_string(atoken);
    const char *expires_on_str = json_object_get_string(expires_on);
    expiration_time = strtol(expires_on_str, NULL, 10);
    const size_t accessTokenStrSize = strlen(accessTokenStr);
    log_info( "Size of access token: %d", accessTokenStrSize);

    char *access = (char *)malloc(accessTokenStrSize + 1);
    memcpy(access, accessTokenStr, accessTokenStrSize);
    access[accessTokenStrSize] = '\0';
    free(accessToken->memory);
    accessToken->memory = access;
    accessToken->size = accessTokenStrSize + 1;

    char * access_copy = malloc(accessToken->size); 
    strcpy(access_copy, accessTokenStr);

    if (strcasecmp(type, "vault") == 0){
        log_info("Value for MHSM token: %s", access);
        tokens[0].accesstoken = access;
        tokens[0].acquired = now;
        tokens[0].expiration = expiration_time;
        tokens[0].size = accessTokenStrSize;
    } else if (strcasecmp(type, "managedHsm") == 0){
        log_info("Value for MHSM token: %s", access);
        tokens[1].accesstoken = access;
        tokens[1].acquired = now;
        tokens[1].expiration = expiration_time;
        tokens[1].size = accessTokenStrSize;
    }
    log_info("Finished refresh for %s at this pid, %d", type, getpid());
}

/**
 * @brief Initializes the tokens so that they both have access values on startup.
 * 
 * @param token_access_mutex mutex to block access/write when updating 
 */
void init_tokens(pthread_mutex_t token_access_mutex){
    
    pthread_mutex_lock(&token_access_mutex);
    refresh("vault");
    refresh("managedHsm");
    pthread_mutex_unlock(&token_access_mutex);
}

/**
 * @brief Updates the token if needed. This function will be ran via thread.
 */
void* update_token(void* arg){
     pthread_detach(pthread_self());
     log_info("Inside of update token function");
     pthread_mutex_t token_access_mutex = PTHREAD_MUTEX_INITIALIZER;
     refresh("vault");
     refresh("managedHsm");
     
     //To alter/test this, change the times and conditionals
     init_tokens(token_access_mutex);
     while (1)
     {
        time_t now = time(NULL);
        if(((now - tokens[0].acquired) > 1800) || (tokens[0].expiration <= now)){
            pthread_mutex_lock(&token_access_mutex);
            //REFRESH TOKEN FOR VAULT
            refresh("vault");
            pthread_mutex_unlock(&token_access_mutex);
            
        }
        if(((now - tokens[1].acquired) > 1800) || (tokens[1].expiration <= now)){
            pthread_mutex_lock(&token_access_mutex);
            //REFRESH TOKEN FOR MHSM
            refresh("managedHsm");
            pthread_mutex_unlock(&token_access_mutex);
        }
        sleep(60);
     }
}

/**
 * @brief Get the access token value based on the type passed in. 
 * 
 * @param type String that has which type of access token to recieve (vault or managedHsm).
 * @return Specified token
 */
struct Token get_token(char* type){
    //check if values are there and expiration
    //      if so, return it
    //else
    //      refresh
    if (strcasecmp(type, "vault") == 0){
        if(tokens[0].accesstoken != NULL){
            return tokens[0];
        }
        else {
            refresh("vault");
        }
    }else if (strcasecmp(type, "managedHsm") == 0){
        if(tokens[0].accesstoken != NULL){
            return tokens[1];
        }
        else {
            refresh("managedHsm");
        }
    }
}