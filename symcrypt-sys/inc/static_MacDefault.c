//
// static_mMacDefault.c
// Default implementation for macOS static shared object.
//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "wrapper.h"
#include <sys/random.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h> 


SYMCRYPT_ENVIRONMENT_POSIX_USERMODE;

PVOID
SYMCRYPT_CALL
SymCryptCallbackAlloc( SIZE_T nBytes )
{
    // aligned_alloc requires size to be integer multiple of alignment
    SIZE_T cbAllocation = (nBytes + (SYMCRYPT_ASYM_ALIGN_VALUE - 1)) & ~(SYMCRYPT_ASYM_ALIGN_VALUE - 1);

    return aligned_alloc(SYMCRYPT_ASYM_ALIGN_VALUE, cbAllocation);
}

VOID
SYMCRYPT_CALL
SymCryptCallbackFree( VOID * pMem )
{
    free( pMem );
}

// From Linux docs on getrandom:
// RETURN VALUE         top
//        On success, getrandom() returns the number of bytes that were
//        copied to the buffer buf.  This may be less than the number of
//        bytes requested via buflen if either GRND_RANDOM was specified in
//        flags and insufficient entropy was present in the random source or
//        the system call was interrupted by a signal.
//        On error, -1 is returned, and errno is set to indicate the error.
SYMCRYPT_ERROR
SYMCRYPT_CALL
SymCryptCallbackRandom(unsigned char *pbBuffer, size_t cbBuffer)
{
       if (pbBuffer == NULL) {
        return SYMCRYPT_EXTERNAL_FAILURE;
    }

    if (cbBuffer == 0) {
        return 0; // Nothing to fill.
    }

    int urandom_fd = open("/dev/urandom", O_RDONLY);
    if (urandom_fd == -1) {
        return SYMCRYPT_EXTERNAL_FAILURE;
    }

    size_t bytes_read = 0;
    while (bytes_read < cbBuffer) {
        ssize_t result = read(urandom_fd, pbBuffer + bytes_read, cbBuffer - bytes_read);

        if (result < 0 ) {
            // An error occurred during read.
            close(urandom_fd);
            return SYMCRYPT_EXTERNAL_FAILURE;
        }
        if (result == 0) {
            // End of file (should not happen for /dev/urandom)
            close(urandom_fd);
            return SYMCRYPT_EXTERNAL_FAILURE;
        }
        bytes_read += result;
    }

    close(urandom_fd); // Close the file descriptor when done.
    return SYMCRYPT_NO_ERROR; // Success
}



