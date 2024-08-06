#ifndef _MACROS_H_
#define _MACROS_H_

/*
 * This project expects a version of OpenSSL that has the following macros defined.
 * However, no version of OpenSSL in the Nuget repository has these macros defined.
 */

// TODO: Build a modern package of OpenSSL for Windows that has these macros defined. So we don't need this file anymore.

#define EVP_PKEY_ED25519 NID_ED25519
#define NID_ED25519 1087

#define EVP_PKEY_ED448 NID_ED448
#define NID_ED448 1088

#define EVP_PKEY_X25519 NID_X25519
#define NID_X25519 1034

#define EVP_PKEY_X448 NID_X448
#define NID_X448 1035

#endif
