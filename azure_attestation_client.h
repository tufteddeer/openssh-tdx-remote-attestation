#ifndef AZURE_ATTESTATION_H
#define AZURE_ATTESTATION_H

#define AZURE_ATTESTATION_SUCCESS 0
#define AZURE_ATTESTATION_ERROR -1

int validate_azure_jwt(const char* jwt_str);

#endif