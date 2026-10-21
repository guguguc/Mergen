#include <stdio.h>

#include "VMProtectSDK.h"

// The smallest possible test: one guest instruction, `add`. The vm has a real
// opcode for it, so titan's shape matcher should fire without any synthesis.
//
__declspec(noinline) int add_only(int a, int b)
{
    VMProtectBeginUltra("add_only");

    int result = a + b;

    VMProtectEnd();
    return result;
}

int main(void)
{
    printf("add_only(0x12345678, 0x0F0F0F0F) = %08x\n", add_only(0x12345678, 0x0F0F0F0F));
    return 0;
}
