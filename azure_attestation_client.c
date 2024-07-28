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

#include <azure_attestation_client.h>

struct MemoryStruct {
  char *memory;
  size_t size;
};

static size_t WriteMemoryCallback(void *contents, size_t size, size_t nmemb, void *userp) {
  size_t realsize = size * nmemb;
  struct MemoryStruct *mem = (struct MemoryStruct *)userp;

  char *ptr = realloc(mem->memory, mem->size + realsize + 1);
  if (ptr == NULL) {
    // Out of memory
    printf("Not enough memory (realloc returned NULL)\n");
    return 0;
  }

  mem->memory = ptr;
  memcpy(&(mem->memory[mem->size]), contents, realsize);
  mem->size += realsize;
  mem->memory[mem->size] = 0;

  return realsize;
}

const char* fetch_azure_cert(const char *key_id) {

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
    
    curl_easy_setopt(curl, CURLOPT_URL, "https://sharedeus2e.eus2e.attest.azure.net/certs");
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
    
    curl_easy_cleanup(curl);
    curl_global_cleanup();
    free(chunk.memory);
    json_decref(keys_json);

    if (x509_body == NULL) {
        printf("No key found with id %s\n", key_id);
    }
    return x509_body;
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

int azure_key_provider(const jwt_t* jwt, jwt_key_t* key_t) {
    
    const char* algorithm = jwt_alg_str(jwt_get_alg(jwt));
    printf("algo: %s\n", algorithm);
    
    
    const char* key_id = jwt_get_header(jwt, "kid");
         
    const char* x509_body = fetch_azure_cert(key_id);
                    
    const char* pem_header = "-----BEGIN CERTIFICATE-----\n";
    const char* pem_footer = "\n-----END CERTIFICATE-----\n";
    char x509_with_pem_deco[strlen(x509_body) + strlen(pem_header) + strlen(pem_footer)];
                    
    sprintf(x509_with_pem_deco, "%s%s%s", pem_header, x509_body, pem_footer);
                    
    char* public_key_pem = public_key_from_x509(x509_with_pem_deco);
                       
    // TODO: we could return jwt_key_t directly 
    key_t->jwt_key = public_key_pem;
    key_t->jwt_key_len = strlen(public_key_pem);
    
    return 0;
}

int validate_azure_jwt(const char* jwt_str) {
 jwt_t *jwt = NULL;

    int ret = jwt_decode_2(&jwt, jwt_str, azure_key_provider);
    if (ret != 0) {
        char* ex = jwt_exception_str(ret);
        fprintf(stderr, "Error decoding JWT: %s\n", ex);
        return 1;
    }
    // Print the payload
    const char *eatProfile = jwt_get_grant(jwt, "eat_profile");

    printf("eat_profile: %s\n", eatProfile ? eatProfile : "not found");

    int res = strcmp(eatProfile, "https://aka.ms/maa-eat-profile-tdxvm") == 0 ? AZURE_ATTESTATION_SUCCESS : AZURE_ATTESTATION_ERROR;

    // Free the JWT object
    jwt_free(jwt);
    
    return res;
}