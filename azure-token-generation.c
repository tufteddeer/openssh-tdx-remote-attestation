#include "azure-token-generation.h"
#include "curl-util.h"
#include <jansson.h>
#include <curl/curl.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define AZURE_ATTESTATION_ENDPOINT "https://sharedeus2e.eus2e.attest.azure.net/attest/TdxVm?api-version=2023-04-01-preview"
#define TRUSTAUTHORITY_CLI_PATH "/Users/f/Projects/Hochschule/openssh-portable/trustauthority-cli-mock.sh"

const char* QUOTE_PREFIX = "Quote: ";
const char* RUNTIME_DATA_PREFIX = "runtime_data: ";

const char* get_token_from_azure(const char* body) {

    struct MemoryStruct chunk;

    chunk.memory = malloc(1);
    chunk.size = 0;

    CURL *curl;
    CURLcode res;
    curl_global_init(CURL_GLOBAL_DEFAULT);
    curl = curl_easy_init();

    if(!curl) {
        printf("Failed to init curl\n");
        curl_global_cleanup();
        return NULL;
    }

    curl_easy_setopt(curl, CURLOPT_URL, AZURE_ATTESTATION_ENDPOINT);

    struct curl_slist *headers = NULL;
    headers = curl_slist_append(headers, "Content-Type: application/json");
    headers = curl_slist_append(headers, "Accept: application/json");
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, body);

    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&chunk);

    res = curl_easy_perform(curl);

    const char* token = NULL;
    if(res == CURLE_OK) {
        json_error_t error;
        json_t* root = json_loads(chunk.memory, 0, &error);
        token = json_string_value(json_object_get(root, "token"));
            
        printf("token: %s\n", token);
    } else {
        fprintf(stderr, "curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
    }

    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);
    curl_global_cleanup();

    return token;
}

const char* generate_azure_token() {
	printf("generating azure token\n");

	char buffer[10500];
    FILE *pipe;
    int exit_status;

    const char *command = TRUSTAUTHORITY_CLI_PATH;
    printf("Running command %s\n", command);

    // Open the command for reading
    pipe = popen(command, "r");
    if (pipe == NULL) {
        printf("Failed to open command stream\n");
       // exit(8);
        return NULL;
    }
    
    char quote[10500];
    char runtime_data[5000];

    printf("Output from %s:\n", command);
    while (fgets(buffer, sizeof(buffer), pipe) != NULL) {
        printf("\nline: %s", buffer);

        if (strncmp(QUOTE_PREFIX, buffer, strlen(QUOTE_PREFIX)) == 0) {
            printf("found quote\n");
            strncpy(quote, buffer+strlen(QUOTE_PREFIX), sizeof(buffer));
        }
        
        if (strncmp(RUNTIME_DATA_PREFIX, buffer, strlen(RUNTIME_DATA_PREFIX)) == 0) {
            printf("found runtime data\n");
            strcpy(runtime_data, buffer+strlen(RUNTIME_DATA_PREFIX));
        }
    }
    
    // Close the pipe and get the exit status
    exit_status = pclose(pipe);
    if (exit_status == -1) {
        printf("Failed to close command stream\n");
        return NULL;
    }
    
    // Print the exit status
    if (WIFEXITED(exit_status)) {
        printf("\n%s exited with status %d\n", command, WEXITSTATUS(exit_status));
    } else {
        printf("\n%s did not exit normally\n", command);
    }

    printf("quote: %s\n", quote);
    printf("runtime_data: %s\n", runtime_data);

    memset(buffer, 0, 10500);
    
    // remove newline character (would break json)
    quote[strlen(quote)-1] = '\0';
    runtime_data[strlen(runtime_data)-1] = '\0';
    
    sprintf(buffer, "{ \"quote\": \"%s\", \"runtimeData\": { \"data\": \"%s\" , \"dataType\": \"JSON\"}}", quote, runtime_data);
    
    printf("json: %s\n", buffer);

    const char* token = get_token_from_azure(buffer);

    char* t = malloc(strlen(token));
    if (t == NULL) {
		printf("Failed to allocate memory for token\n");
		return NULL;
    }

    strcpy(t, token);
    
    return t;
}
