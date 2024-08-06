/*
 * Copyright (c) 2016 Kurt Roeckx <kurt@roeckx.be>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to
 * deal in the Software without restriction, including without limitation the
 * rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
 * sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 */

#include <stdlib.h>
#include <stdio.h>
#include <openssl/x509.h>
#include "checks.h"
#include "messages.h"
//#include <iostream>

static int LoadCert(const char *certData, unsigned char **buffer, size_t *buflen)
{
    // Calculate the size of the certificate data
    long size = strlen(certData);

    // Allocate memory for the buffer
    *buffer = (unsigned char *)malloc(size);
    if (*buffer == NULL)
    {
        return -1;
    }

    // Copy the certificate data into the buffer
    memcpy(*buffer, certData, size);

    // Set the buffer length
    *buflen = size;

    return 0;
}


int main(int argc, char *argv[])
{
    unsigned char *buffer;
    size_t buflen;

    if (argc != 2)
    {
        printf("Usage: x509lint \"Certificate Contents\"\n");
        exit(1);
    }

    if (LoadCert(argv[1], &buffer, &buflen) != 0)
    {
        fprintf(stderr, "Unable to process certificate data\n");
        exit(1);
    }
    X509 *x509 = GetCert(buffer, buflen, PEM);
    if (x509 == NULL)
    {
        printf("E: Unable to parse certificate\n");
        return 1;
    }

    check_init();
    
    check(buffer, buflen, PEM, GetType(x509));

    char *m = get_messages();
    printf("%s", m);
    free(m);

    free(buffer);
    X509_free(x509);

    check_finish();

    return 0;
}