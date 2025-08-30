#ifndef __VBTPATCH_H
#define __VBTPATCH_H

#define DEBUG_MESSAGE_LENGTH 1024

#include <Uefi.h>

VOID
    EFIAPI
    PrintFuncNameMessage(
        IN CONST BOOLEAN IsError,
        IN CONST CHAR8 *FuncName,
        IN CONST CHAR16 *FormatString,
        ...);

#define PrintDebug(Format, ...) \
  PrintFuncNameMessage(FALSE, __FUNCTION__, Format, ##__VA_ARGS__)

#define PrintError(Format, ...) \
  PrintFuncNameMessage(TRUE, __FUNCTION__, Format, ##__VA_ARGS__)

#endif // __VBTPATCH_H
