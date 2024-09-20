#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <jwt.h>
#include <curl/curl.h>
#include <jansson.h>
#include <openssl/x509.h>
#include <openssl/bio.h>
#include <openssl/pem.h>
#include "digest.h"
#include "log.h"
#include <ctype.h>

#include <azure_attestation_client.h>
#include "curl-util.h"

const char* fetch_azure_cert(const char *url, const char *key_id) {

    struct MemoryStruct chunk;

    chunk.memory = malloc(1);  // will be grown as needed by the realloc above
    chunk.size = 0;
  
    CURL *curl;
    CURLcode res;
    curl_global_init(CURL_GLOBAL_DEFAULT);
    curl = curl_easy_init();
    if (!curl) {
        fprintf(stderr, "Failed to initialize curl\n");
        free(chunk.memory);
        return NULL;
    }
    
    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&chunk);
    
    res = curl_easy_perform(curl);
    
    if(res != CURLE_OK) {
          fprintf(stderr, "curl_easy_perform() failed: %s\n",
                  curl_easy_strerror(res));
          curl_easy_cleanup(curl);
          free(chunk.memory);
          return NULL;
    }
    //printf("Response: %s\n", chunk.memory);
        
    json_error_t error;
    json_t* keys_json = json_loads(chunk.memory, 0, &error);
        
    json_t* keys_array = json_object_get(keys_json, "keys");

    size_t i;
    size_t size = json_array_size(keys_array);
    
    const char* x509_body = NULL;
    
    for (i = 0; i < size; i++) {
        json_t* ele = json_array_get(keys_array, i);
            
        const char* current_key_id = json_string_value(json_object_get(ele, "kid"));
        printf("found key with id %s\n", key_id);
            
        if (strcmp(current_key_id, key_id) == 0) {
            printf("found correct key %s\n", current_key_id);
                
            x509_body = json_string_value(json_array_get(json_object_get(ele, "x5c"), 0));
            printf("x509 body: %s\n", x509_body);
            
            break;
        }
    }
    
    char *x509_body_buff = strdup(x509_body);
    curl_easy_cleanup(curl);
    curl_global_cleanup();
    free(chunk.memory);
    json_decref(keys_json);

    if (x509_body == NULL) {
        printf("No key found with id %s\n", key_id);
    }
    return x509_body_buff;
}

char* public_key_from_x509(const char *x509_cert) {

    BIO *bio_mem = BIO_new_mem_buf(x509_cert, strlen(x509_cert));
    if (!bio_mem) {
        fprintf(stderr, "Failed to create BIO\n");
        return NULL;
    }

    X509 *cert = PEM_read_bio_X509(bio_mem, NULL, NULL, NULL);
    if (cert == NULL) {
        fprintf(stderr, "Failed to parse certificate\n");
        BIO_free(bio_mem);
        return NULL;
    }
    EVP_PKEY *pkey = X509_get_pubkey(cert);
    if (pkey == NULL) {
        fprintf(stderr, "Failed to extract public key from certificate\n");
        X509_free(cert);
        BIO_free(bio_mem);
        return NULL;
    }
    
    BIO *bio = BIO_new(BIO_s_mem());
    if (!bio) {
        fprintf(stderr, "Failed to create BIO\n");
        EVP_PKEY_free(pkey);
        X509_free(cert);
        BIO_free(bio_mem);
        return NULL;
    }
    
    if (PEM_write_bio_PUBKEY(bio, pkey) != 1) {
        fprintf(stderr, "Failed to write public key in PEM format\n");
        BIO_free(bio);
        EVP_PKEY_free(pkey);
        X509_free(cert);
        BIO_free(bio_mem);
        return NULL;
    }
    
    BUF_MEM *bptr;
    BIO_get_mem_ptr(bio, &bptr);

    // Copy the PEM data to a new buffer
    char *pem_data = malloc(bptr->length + 1);
    if (!pem_data) {
        fprintf(stderr, "Failed to allocate memory for PEM data\n");
        BIO_free(bio);
        EVP_PKEY_free(pkey);
        X509_free(cert);
        return NULL;
    }
    memcpy(pem_data, bptr->data, bptr->length);
    pem_data[bptr->length] = '\0';
    
    return pem_data;
}

// https://stackoverflow.com/questions/744766/how-to-compare-ends-of-strings-in-c
int ends_with(const char *str, const char *suffix)
{
    if (!str || !suffix)
        return 0;
    size_t lenstr = strlen(str);
    size_t lensuffix = strlen(suffix);
    if (lensuffix >  lenstr)
        return 0;
    return strncmp(str + lenstr - lensuffix, suffix, lensuffix) == 0;
}

int azure_key_provider(const jwt_t* jwt, jwt_key_t* key_t) {
    
    const char* algorithm = jwt_alg_str(jwt_get_alg(jwt));
    printf("algo: %s\n", algorithm);
    
    
    const char* key_id = jwt_get_header(jwt, "kid");
    const char* url = jwt_get_header(jwt, "jku");
    
    debug_f("got X509 certificates url: %s", url);

    const char *expected_cert_url_suffix = "azure.net/certs";
    
    if (ends_with(url, expected_cert_url_suffix)) {
        debug_f("certificate url is from azure");
    } else {
        debug_f("certificate url may not be from azure. aborting\n", expected_cert_url_suffix);
        return -1;
    }

         
    const char* x509_body = fetch_azure_cert(url, key_id);
                    
    const char* pem_header = "-----BEGIN CERTIFICATE-----\n";
    const char* pem_footer = "\n-----END CERTIFICATE-----\n\0";
    
    char x509_with_pem_deco[strlen(x509_body) + strlen(pem_header) + strlen(pem_footer)];
                    
    sprintf(x509_with_pem_deco, "%s%s%s", pem_header, x509_body, pem_footer);
                    
    char* public_key_pem = public_key_from_x509(x509_with_pem_deco);
                       
    // TODO: we could return jwt_key_t directly 
    key_t->jwt_key = public_key_pem;
    key_t->jwt_key_len = strlen(public_key_pem);
    
    free(x509_body);
    return 0;
}

// check if the expected nonce matches the received nonce
// the expected nonce is raw data
// the received nonce is upper case SHA5125 and should be equal to sha512(expected)
int validate_nonce(const char *expected, const char *received) {
	size_t len = ssh_digest_bytes(SSH_DIGEST_SHA512);
    u_char *hash = malloc(len);
    ssh_digest_memory(SSH_DIGEST_SHA512, expected, strlen(expected), hash, len);

    // Convert the hash to a hex string for comparison
    char hex_output[len * 2 + 1];
    for (size_t i = 0; i < len; i++) {
        snprintf(hex_output + 2 * i, 3, "%02X", hash[i]);
    }
    hex_output[len * 2] = '\0';
    
    debug_f("expected nonce: %s", hex_output);
    debug_f("received nonce: %s", received);

    if (strcmp(hex_output, received) == 0) {
        return AZURE_ATTESTATION_SUCCESS;
    } else {
    	return AZURE_ATTESTATION_ERROR;
    }
}

const char* get_user_data_from_json(jwt_t *jwt) {
	json_t *json_obj;
    json_error_t error;
    
    const char *ms_runtime_str = jwt_get_grants_json(jwt, "x-ms-runtime");
    if (!ms_runtime_str) {
    	debug_f("\"x-ms-runtime\" field not found");
     	return NULL;
    }
    debug_f("ms_runtime str: %s", ms_runtime_str);

    json_obj = json_loads(ms_runtime_str, 0, &error);
    if (!json_obj) {
        debug_f("Error parsing JSON: %s\n", error.text);
        return NULL;
    }
    
    json_t *user_data = json_object_get(json_obj, "user-data");
    if (!user_data) {
    	debug_f("\"user-data\" field not found\n");
        json_decref(json_obj);
        return NULL;
    }
    
    const char *user_data_str = json_string_value(user_data);
    if (!user_data_str) {
        debug_f("\"user-data\" is not a string value\n");
    }

    const char *result = malloc(strlen(user_data_str));
    strcpy(result, user_data_str);
    debug_f("user data: %s", user_data_str);
    json_decref(json_obj);
    
    return result;
}
int validate_azure_jwt(const char *jwt_str, const char *nonce) {
	jwt_t *jwt = NULL;

    int ret = jwt_decode_2(&jwt, jwt_str, azure_key_provider);
    if (ret != 0) {
        char* ex = jwt_exception_str(ret);
        fprintf(stderr, "Error decoding JWT: %s\n", ex);
        return 1;
    }

    const char *eatProfile = jwt_get_grant(jwt, "eat_profile");
    const char *msAttestationType = jwt_get_grant(jwt, "x-ms-attestation-type");
    const char *msComplianceStatus = jwt_get_grant(jwt, "x-ms-compliance-status");

    int res = AZURE_ATTESTATION_SUCCESS;

    if (strcmp(eatProfile, "https://aka.ms/maa-eat-profile-tdxvm") != 0) {
        debug_f("attestation failure: eat_profile (expected: https://aka.ms/maa-eat-profile-tdxvm, actual: %s)", eatProfile);
        res = AZURE_ATTESTATION_ERROR;
    } else if (strcmp(msAttestationType, "tdxvm") != 0) {
        debug_f("attestation failure: x-ms-attestation-type (expected: tdxvm, actual: %s)", msAttestationType);
        res = AZURE_ATTESTATION_ERROR;
    }  else if (strcmp(msComplianceStatus, "azure-compliant-cvm") != 0) {
        debug_f("attestation failure: x-ms-compliance-status (expected: azure-compliant-cvm, actual: %s)", msComplianceStatus);
        res = AZURE_ATTESTATION_ERROR;
    }

    debug_f("valid eat_profile: %s", eatProfile);
    debug_f("valid x-ms-compliance-status: %s", msComplianceStatus);
    debug_f("valid x-ms-attestation-type: %s", msAttestationType);

    if (res == AZURE_ATTESTATION_SUCCESS) {
    	
    	const char* user_data_str = get_user_data_from_json(jwt);
        if (!user_data_str) {
        	debug_f("failed to get user_data from jwt");
			return AZURE_ATTESTATION_ERROR;
		}
        res = validate_nonce(nonce, user_data_str);
        
        free(user_data_str);
    }

    jwt_free(jwt);
    
    return res;
}