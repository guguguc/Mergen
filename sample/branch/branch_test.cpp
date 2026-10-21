#include <stdio.h>

#include "VMProtectSDK.h"

__declspec(noinline) int branch_only(int a, int b)
{
    VMProtectBeginUltra("branch_only");

    int result;
    if (a > b)
        result = a - b;
    else
        result = a ^ b;

    VMProtectEnd();
    return result;
}

int main(void)
{
    printf("branch_only(0x12345678, 0x0F0F0F0F) = %08x\n",
           branch_only(0x12345678, 0x0F0F0F0F));
    return 0;
}
