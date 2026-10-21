#include <stdio.h>

#include "VMProtectSDK.h"

// A loop with a carried accumulator: the restored code should keep the counter
// and the running sum as real values.
//
__declspec(noinline) int compute_sum(int n)
{
    VMProtectBeginUltra("compute_sum");

    int sum = 0;
    for (int i = 1; i <= n; i++)
    {
        sum += i * i;
    }

    VMProtectEnd();
    return sum;
}

// A multi-way branch: the restored code should show a switch or a chain of
// comparisons.
//
__declspec(noinline) int classify(int x)
{
    VMProtectBeginUltra("classify");

    int result;
    if (x < 0)
        result = -1;
    else if (x == 0)
        result = 0;
    else if (x < 10)
        result = 1;
    else if (x < 100)
        result = 2;
    else
        result = 3;

    VMProtectEnd();
    return result;
}

// Bit mixing with a constant: easy to recognize in the restored IR even if the
// optimizer moves things around.
//
__declspec(noinline) unsigned int mix(unsigned int seed)
{
    VMProtectBeginUltra("mix");

    unsigned int value = seed;
    for (int i = 0; i < 8; i++)
    {
        value ^= value << 13;
        value ^= value >> 17;
        value ^= value << 5;
    }

    VMProtectEnd();
    return value;
}

int main(void)
{
    printf("compute_sum(10) = %d\n", compute_sum(10));
    printf("classify(7)     = %d\n", classify(7));
    printf("classify(-3)    = %d\n", classify(-3));
    printf("mix(0x12345678) = %08x\n", mix(0x12345678u));
    return 0;
}
