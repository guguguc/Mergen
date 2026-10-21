#include <stdio.h>

#include "VMProtectSDK.h"

// The smallest possible test: one guest instruction, `xor`.
//
__declspec(noinline) int xor_only(int a, int b)
{
    VMProtectBeginUltra("xor_only");

    int result = a ^ b;

    VMProtectEnd();
    return result;
}

int main(void)
{
    printf("xor_only(0x12345678, 0x0F0F0F0F) = %08x\n", xor_only(0x12345678, 0x0F0F0F0F));
    return 0;
}
