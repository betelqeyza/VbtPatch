#include <Uefi.h>
#include <Library/UefiLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/IniParsingLib.h>
#include <Protocol/PciIo.h>
#include "Filesystem.h"
#include "VbtPatch.h"

BOOLEAN mLaunchEfi = FALSE;
BOOLEAN mLogToFile = FALSE;
BOOLEAN mVerboseMode = FALSE;
CHAR16 *mEfiFilePath = NULL;
EFI_HANDLE mVbtPatchImage;
EFI_LOADED_IMAGE_PROTOCOL *mVbtPatchImageInfo;
EFI_FILE_HANDLE mLogFileHandle = NULL;
EFI_FILE_HANDLE mVolumeRoot = NULL;

/*
 * 0000:00:02.0
 * Intel Graphics Card PCI bus
 */
#define IGD_BUS 0x00
#define IGD_DEV 0x02
#define IGD_FUNC 0x00

/* same as OPREGION_PCI_ADDR */
#define ASLS_OFFSET 0xFC

/* Should actually be 8192 */
#define OPREGION_SIZE 0x10000

#define OPREGION_SIGNATURE "IntelGraphicsMem"
#define VBT_SIGNATURE "$VBT"
#define VBT_SIGNATURE_LEN 4

/* Hardcoded location, no longer necessary */
#define HARDCODED_VBT_OFFSET 0x2000

/* Main screen */
#define DEVICE_HANDLE_LFP1 0x0008

/* Ghost screen */
#define DEVICE_HANDLE_LFP2 0x0080

#define BDB_GENERAL_DEFINITIONS_ID 2
#define YESNO(val) ((val) ? L"yes" : L"no")

#pragma pack(1)
/* struct vbt_header */
typedef struct
{
  CHAR8 Signature[20]; /* "$VBT ALDERLAKE-P" */
  UINT16 Version;
  UINT16 HeaderSize;
  UINT16 VbtSize;
  UINT8 VbtChecksum;
  UINT8 Reserved;
  UINT32 BdbOffset;
  UINT32 AimOffset[4];
} VBT_HEADER;

/*struct bdb_header */
typedef struct
{
  UINT8 Signature[16];
  UINT16 Version;
  UINT16 HeaderSize;
  UINT16 BdbSize;
} BDB_HEADER;

/* struct bdb_block_entry */
typedef struct
{
  UINT8 Id;
  UINT32 Size;
  UINT8 Data[];
} BDB_BLOCK;

/* struct child_device_config */
typedef struct
{
  UINT16 Handle;
  UINT16 DeviceType;
  UINT8 Padding[35]; /* version 251 */
} BDB_CHILD_DEVICE_CONFIG;

/* struct bdb_general_definitions */
typedef struct
{
  UINT8 CrtDdcGmbusPin;
  UINT8 DpmsNonAcpi : 1;
  UINT8 SkipBootCrtDetect : 1;
  UINT8 DpmsAim : 1;
  UINT8 Rsvd1 : 5;
  UINT8 BootDisplay[2];
  UINT8 ChildDevSize;
  UINT8 Devices[];
} BDB_GENERAL_DEFINITIONS;
#pragma pack()

VOID
    EFIAPI
    PrintFuncNameMessage(
        IN CONST BOOLEAN IsError,
        IN CONST CHAR8 *FuncName,
        IN CONST CHAR16 *FormatString,
        ...)
{
  VA_LIST Marker;
  CHAR16 *Buffer;
  UINTN BufferSize;
  CHAR8 *AsciiBuffer;
  UINTN AsciiBufferSize;

  if ((FuncName == NULL) || (FormatString == NULL) || !(IsError || mVerboseMode || mLogToFile))
  {
    return;
  }

  /* Generate the main message. */
  BufferSize = DEBUG_MESSAGE_LENGTH * sizeof(CHAR16);
  Buffer = (CHAR16 *)AllocatePool(BufferSize);
  if (Buffer == NULL)
  {
    return;
  }
  VA_START(Marker, FormatString);
  UnicodeVSPrint(Buffer, BufferSize, FormatString, Marker);
  VA_END(Marker);

  if (IsError || mVerboseMode)
  {
    /* Output using apropriate colors. */
    gST->ConOut->SetAttribute(gST->ConOut, EFI_DARKGRAY);
    AsciiPrint("%.10a ", FuncName);
    gST->ConOut->SetAttribute(gST->ConOut, IsError ? EFI_YELLOW : EFI_LIGHTGRAY);
    if ((gST != NULL) && (gST->ConOut != NULL))
    {
      gST->ConOut->OutputString(gST->ConOut, Buffer);
    }

    /* Cleanup. */
    gST->ConOut->SetAttribute(gST->ConOut, EFI_LIGHTGRAY);
  }

  if (mLogToFile)
  {
    if (mLogFileHandle != NULL)
    {
      AsciiBufferSize = AsciiStrLen(FuncName) + 2 + StrLen(Buffer) + 1;
      AsciiBuffer = AllocatePool(AsciiBufferSize);
      if (AsciiBuffer != NULL)
      {
        AsciiSPrint(AsciiBuffer, AsciiBufferSize, "%a: %s", FuncName, Buffer);
        AsciiBufferSize = AsciiStrLen(AsciiBuffer);
        mLogFileHandle->SetPosition(mLogFileHandle, (UINT64)-1);
        mLogFileHandle->Write(mLogFileHandle, &AsciiBufferSize, AsciiBuffer);
        mLogFileHandle->Flush(mLogFileHandle);
        FreePool(AsciiBuffer);
      }
    }
  }

  FreePool(Buffer);
}

VOID WaitForEnter(
    IN BOOLEAN PrintMessage)
{
  EFI_INPUT_KEY Key;
  UINTN EventIndex;

  if (PrintMessage)
  {
    PrintDebug(L"Press Enter to continue\n");
  }

  gST->ConIn->Reset(gST->ConIn, FALSE);
  do
  {
    gBS->WaitForEvent(1, &gST->ConIn->WaitForKey, &EventIndex);
    gST->ConIn->ReadKeyStroke(gST->ConIn, &Key);
  } while (Key.UnicodeChar != CHAR_CARRIAGE_RETURN);
}

VOID WaitForEnterAndStall(
    IN BOOLEAN PrintMessage)
{
  WaitForEnter(PrintMessage);
  gBS->Stall(1000 * 1000); /* 1 second */
}

BOOLEAN
ReadConfig(VOID)
{
  EFI_STATUS Status;
  CHAR16 *FilePath = NULL;
  UINT8 *FileContents;
  UINTN FileBytes;
  VOID *Context;
  UINTN Num;

  if (mEfiFilePath == NULL)
    return FALSE;

  Status = GetFilenameInSameDirectory(mEfiFilePath, L"VbtPatch.ini", (VOID **)&FilePath);
  if (EFI_ERROR(Status) || (FilePath == NULL) || !FileExists(mVolumeRoot, FilePath))
  {
    if (FilePath != NULL)
      FreePool(FilePath);
    return FALSE;
  }

  Status = FileRead(mVolumeRoot, FilePath, (VOID **)&FileContents, &FileBytes);
  FreePool(FilePath);
  if (EFI_ERROR(Status))
    return FALSE;

  Context = OpenIniFile(FileContents, FileBytes);
  if (Context == NULL)
  {
    FreePool(FileContents);
    return FALSE;
  }

  /* verbose */
  Status = GetDecimalUintnFromDataFile(Context, "config", "verbose", &Num);
  mVerboseMode = (!EFI_ERROR(Status) && (Num == 1));

  /* logfile */
  Status = GetDecimalUintnFromDataFile(Context, "config", "logfile", &Num);
  mLogToFile = (!EFI_ERROR(Status) && (Num == 1));

  /* launch_efi */
  Status = GetDecimalUintnFromDataFile(Context, "config", "launch_efi", &Num);
  mLaunchEfi = (!EFI_ERROR(Status) && (Num == 1));

  CloseIniFile(Context);
  FreePool(FileContents);
  return TRUE;
}

/* static int child_device_expected_size(u16 version) */
INT32
ChildDeviceExpectedSize(UINT16 version)
{
  if (version > 256)
    return -1;
  else if (version >= 256)
    return 40;
  else if (version >= 216)
    return 39;
  else if (version >= 196)
    return 38;
  else if (version >= 195)
    return 37;
  else if (version >= 111)
    return 33;
  else if (version >= 106)
    return 27;
  else
    return 22;
}

/*
 * bdb_find_section
 * _get_blocksize
 * get_blocksize
 */
BDB_BLOCK
*FindBdbBlock(BDB_HEADER *Bdb, UINT8 BlockId)
{
  UINT8 *Ptr = (UINT8 *)Bdb + Bdb->HeaderSize;
  UINT8 *End = (UINT8 *)Bdb + Bdb->BdbSize;
  while (Ptr < End)
  {
    UINT8 Id = *Ptr;
    UINT16 Size = *(UINT16 *)(Ptr + 1);
    if (Id == BlockId)
    {
      BDB_BLOCK *Block = AllocatePool(sizeof(BDB_BLOCK) + Size);
      if (Block == NULL)
        return NULL;
      Block->Id = Id;
      Block->Size = Size;
      CopyMem(Block->Data, Ptr + 3, Size);
      return Block;
    }
    Ptr += Size + 3; /* ID (1) + Size (2) + Data */
  }
  return NULL;
}

VOID DumpChildDevices(BDB_GENERAL_DEFINITIONS *Defs, UINT16 BlockSize, UINT8 ChildDevNum, UINT8 ChildDevSize)
{
  BDB_CHILD_DEVICE_CONFIG *Child = AllocateZeroPool(sizeof(BDB_CHILD_DEVICE_CONFIG));
  if (Child == NULL)
  {
    PrintError(L"Child device buffer allocation failed!\n");
    return;
  }

  for (UINT8 i = 0; i < ChildDevNum; i++)
  {
    UINTN CopySize = ChildDevSize < sizeof(BDB_CHILD_DEVICE_CONFIG) ? ChildDevSize : sizeof(BDB_CHILD_DEVICE_CONFIG);
    CopyMem(Child, Defs->Devices + i * ChildDevSize, CopySize);
    PrintDebug(L"Child %d: Handle=0x%04x Type=0x%04x\n", i, Child->Handle, Child->DeviceType);
  }

  FreePool(Child);
}

/* static void dump_general_definitions */
VOID DumpGeneralDefinitions(BDB_GENERAL_DEFINITIONS *Defs, UINT16 BlockSize)
{
  UINT8 ChildDevNum = (BlockSize - sizeof(BDB_GENERAL_DEFINITIONS)) / Defs->ChildDevSize;
  PrintDebug(L"CRT DDC GMBUS addr: 0x%02x\n", Defs->CrtDdcGmbusPin);
  PrintDebug(L"Use DPMS on AIM devices: %s\n", YESNO(Defs->DpmsAim));
  PrintDebug(L"Skip CRT detect at boot: %s\n", YESNO(Defs->SkipBootCrtDetect));
  PrintDebug(L"Use Non ACPI DPMS CRT power states: %s\n", YESNO(Defs->DpmsNonAcpi));
  PrintDebug(L"Boot display type: 0x%02x%02x\n", Defs->BootDisplay[1], Defs->BootDisplay[0]);
  PrintDebug(L"Child device size: %d\n", Defs->ChildDevSize);
  PrintDebug(L"Child device count: %d\n", ChildDevNum);

  DumpChildDevices(Defs, BlockSize, ChildDevNum, Defs->ChildDevSize);
}

/*
 * Boot Setting File Specification Release 1.0
 *
 * The checksum is calculated by adding the values starting at the BeginAddr and through the end of the
 * configuration element located at the EndAddr and storing the sum at Location. The algorithms for the
 * one byte checksum calculations follows
 *
 * More at https://www.intel.com/content/www/us/en/content-details/671444/boot-setting-file-specification-release-1-0.html
 */
VOID UpdateVbtChecksum(VBT_HEADER *Vbt)
{
  UINT8 Checksum = 0;
  for (UINTN i = 0; i < Vbt->VbtSize; i++)
  {
    Checksum += ((UINT8 *)Vbt)[i];
  }
  Vbt->VbtChecksum = -Checksum;
  PrintDebug(L"Checksum Updated: 0x%02x\n", Vbt->VbtChecksum);
}

/* bool intel_bios_is_valid_vbt(struct intel_display *display, const void *buf, size_t size) */
EFI_STATUS
IsValidVBT(VBT_HEADER *vbt, UINTN size)
{
  if (!vbt || sizeof(VBT_HEADER) > size)
  {
    PrintError(L"VBT header incomplete\n");
    return EFI_INVALID_PARAMETER;
  }
  if (CompareMem(vbt->Signature, VBT_SIGNATURE, VBT_SIGNATURE_LEN) != 0)
  {
    PrintError(L"VBT invalid signature\n");
    return EFI_INVALID_PARAMETER;
  }
  if (vbt->VbtSize > size)
  {
    PrintError(L"VBT incomplete (vbt_size overflows)\n");
    return EFI_INVALID_PARAMETER;
  }
  UINTN bdb_offset = vbt->BdbOffset;
  if (bdb_offset + sizeof(BDB_HEADER) > vbt->VbtSize)
  {
    PrintError(L"BDB header incomplete\n");
    return EFI_INVALID_PARAMETER;
  }
  BDB_HEADER *bdb = (BDB_HEADER *)((CHAR8 *)vbt + bdb_offset);
  if (bdb_offset + bdb->BdbSize > vbt->VbtSize)
  {
    PrintError(L"BDB incomplete\n");
    return EFI_INVALID_PARAMETER;
  }
  return EFI_SUCCESS;
}

UINT8 *
FindBdbBlockInplace(BDB_HEADER *Bdb, UINT8 BlockId, UINT16 *OutSize)
{
  UINT8 *Ptr = (UINT8 *)Bdb + Bdb->HeaderSize;
  UINT8 *End = (UINT8 *)Bdb + Bdb->BdbSize;

  while (Ptr + 3 <= End)
  {
    UINT8 Id = Ptr[0];
    UINT16 Size = Ptr[1] | (Ptr[2] << 8);
    if (Ptr + 3 + Size > End)
      return NULL; /* malformed */
    if (Id == BlockId)
    {
      if (OutSize)
        *OutSize = Size;
      return Ptr + 3; /* pointer INTO THE ORIGINAL BUFFER */
    }
    Ptr += 3 + Size;
  }
  return NULL;
}

EFI_STATUS
PatchLfp2_Inplace(UINT8 *VbtBufBase,                /* Buffer + VbtOffset (pointer into your allocated Buffer) */
                  EFI_PHYSICAL_ADDRESS VbtPhysAddr, /* physical = ASLS + VbtOffset */
                  UINT8 *GdData, UINT16 GdLen)      /* GdData returned by FindBdbBlockInplace, GdLen = block size */
{
  if (!VbtBufBase || !GdData || GdLen < sizeof(BDB_GENERAL_DEFINITIONS))
    return EFI_INVALID_PARAMETER;

  BDB_GENERAL_DEFINITIONS *Defs = (BDB_GENERAL_DEFINITIONS *)GdData;
  UINT8 child_sz = Defs->ChildDevSize;

  if (child_sz < 4)
  {
    PrintError(L"child_sz too small: %u\n", child_sz);
    return EFI_COMPROMISED_DATA;
  }

  /* compute how many child entries fit into this block */
  UINTN hdr_size = sizeof(BDB_GENERAL_DEFINITIONS);
  if (GdLen < hdr_size)
    return EFI_COMPROMISED_DATA;
  UINTN child_cnt = (GdLen - hdr_size) / child_sz;

  for (UINTN i = 0; i < child_cnt; i++)
  {
    UINT8 *entry = Defs->Devices + i * child_sz;

    /* read in little-endian order */
    UINT16 handle = (UINT16)(entry[0] | (entry[1] << 8));
    UINT16 dtype = (UINT16)(entry[2] | (entry[3] << 8));

    PrintDebug(L"Child %u: Handle=0x%04x Type=0x%04x\n", i, handle, dtype);

    if (handle == DEVICE_HANDLE_LFP2)
    {
      PrintDebug(L"LFP2 found (index %u), old type=0x%04x. Patching...\n", i, dtype);

      /* modify in-place in the Buffer */
      entry[2] = 0x00;
      entry[3] = 0x00;

      /* recompute VBT checksum in the buffer */
      VBT_HEADER *VbtHdrInBuf = (VBT_HEADER *)VbtBufBase;
      UpdateVbtChecksum(VbtHdrInBuf);

      /* compute offsets to write back to physical OpRegion */
      /* offset of GeneralDefs within VBT (bytes from VbtBufBase) */
      UINTN offset_into_vbt = (UINTN)((UINT8 *)GdData - VbtBufBase);

      /* physical address of this child entry: */
      EFI_PHYSICAL_ADDRESS child_phys = VbtPhysAddr + offset_into_vbt + hdr_size + i * child_sz;

      /* write modified child entry bytes to physical memory (child_sz bytes) */
      CopyMem((VOID *)child_phys, entry, child_sz);
      PrintDebug(L"Child entry -> phys 0x%lx (len %u)\n", child_phys, child_sz);

      /* oh also write checksum byte to physical memory */
      /* find checksum offset inside VBT buffer */
      EFI_PHYSICAL_ADDRESS checksum_phys = VbtPhysAddr + ((UINT8 *)&VbtHdrInBuf->VbtChecksum - (UINT8 *)VbtHdrInBuf);
      CopyMem((VOID *)checksum_phys, &VbtHdrInBuf->VbtChecksum, 1);
      PrintDebug(L"Checksum written -> phys 0x%lx value=0x%02x\n", checksum_phys, VbtHdrInBuf->VbtChecksum);

      return EFI_SUCCESS;
    }
  }

  PrintError(L"LFP2 is not found\n");
  return EFI_NOT_FOUND;
}

EFI_STATUS
HandleIgdVbt(VOID)
{
  EFI_STATUS Status;
  EFI_PCI_IO_PROTOCOL *PciIo;
  UINTN HandleCount;
  EFI_HANDLE *HandleBuffer;
  BOOLEAN FoundIgd = FALSE;
  Status = gBS->LocateHandleBuffer(ByProtocol,
                                   &gEfiPciIoProtocolGuid,
                                   NULL,
                                   &HandleCount,
                                   &HandleBuffer);
  if (EFI_ERROR(Status))
  {
    PrintError(L"Failed to locate PCI handles: %r\n", Status);
    return Status;
  }

  for (UINTN i = 0; i < HandleCount; i++)
  {
    Status = gBS->HandleProtocol(HandleBuffer[i],
                                 &gEfiPciIoProtocolGuid,
                                 (VOID **)&PciIo);
    if (EFI_ERROR(Status))
      continue;

    UINTN Segment, Bus, Device, Function;
    Status = PciIo->GetLocation(PciIo, &Segment, &Bus, &Device, &Function);
    if (EFI_ERROR(Status))
      continue;

    if (Bus == IGD_BUS && Device == IGD_DEV)
    {
      FoundIgd = TRUE;
      PrintDebug(L"Scanning IGD PCI device: %02x:%02x.%x\n", Bus, Device, Function);

      UINT32 ASLS = 0;
      Status = PciIo->Pci.Read(PciIo, EfiPciIoWidthUint32, ASLS_OFFSET, 1, &ASLS);
      if (EFI_ERROR(Status))
      {
        PrintError(L"ASLS not found: %r\n", Status);
        FreePool(HandleBuffer);
        return Status;
      }

      PrintDebug(L"ASLS address: 0x%x\n", ASLS);
      EFI_PHYSICAL_ADDRESS OpRegionAddr = ASLS;
      UINTN OpRegionSize = OPREGION_SIZE;

      CHAR8 *Buffer = NULL;
      Status = gBS->AllocatePool(EfiBootServicesData, OpRegionSize, (VOID **)&Buffer);
      if (EFI_ERROR(Status))
      {
        PrintError(L"Pool allocation failed: %r\n", Status);
        FreePool(HandleBuffer);
        return Status;
      }

      CopyMem(Buffer, (VOID *)OpRegionAddr, OpRegionSize);
      PrintDebug(L"OpRegion address read from 0x%lx, size: %d\n", OpRegionAddr, OpRegionSize);

      if (CompareMem(Buffer, OPREGION_SIGNATURE, 16) != 0)
      {
        PrintError(L"OpRegion signature mismatch, expected: 'IntelGraphicsMem'!\n");
        gBS->FreePool(Buffer);
        FreePool(HandleBuffer);
        return EFI_NOT_FOUND;
      }

      CHAR8 *VbtScanPtr = Buffer;
      UINTN VbtScanEnd = OpRegionSize - VBT_SIGNATURE_LEN;
      EFI_PHYSICAL_ADDRESS VbtAddr = 0;
      VBT_HEADER *VbtHeader = NULL;

      for (UINTN j = 0; j < VbtScanEnd; j++)
      {
        if (CompareMem(VbtScanPtr + j, VBT_SIGNATURE, VBT_SIGNATURE_LEN) == 0)
        {
          VbtHeader = (VBT_HEADER *)(VbtScanPtr + j);
          VbtAddr = OpRegionAddr + j;
          PrintDebug(L"$VBT found! RAM: 0x%p, Physical: 0x%lx\n", VbtHeader, VbtAddr);
          break;
        }
      }

      if (!VbtHeader)
      {
        PrintError(L"$VBT header is not found!!\n");
        gBS->FreePool(Buffer);
        FreePool(HandleBuffer);
        return EFI_NOT_FOUND;
      }

      Status = IsValidVBT(VbtHeader, OpRegionSize - ((UINT8 *)VbtHeader - (UINT8 *)Buffer));
      if (EFI_ERROR(Status))
      {
        PrintError(L"VBT is invalid, status: %r\n", Status);
        gBS->FreePool(Buffer);
        FreePool(HandleBuffer);
        return Status;
      }

      PrintDebug(L"VBT found, Size: %d, BDB Offset: %d, Version: %d\n",
                 VbtHeader->VbtSize, VbtHeader->BdbOffset, VbtHeader->Version);
      PrintDebug(L"VBT Header @ Buffer+0x%x (absolute 0x%lx)\n",
                 HARDCODED_VBT_OFFSET, (EFI_PHYSICAL_ADDRESS)VbtHeader);
      PrintDebug(L"VBT Signature: '%.4a'\n", VbtHeader->Signature);

      BDB_HEADER *Bdb = (BDB_HEADER *)((UINT8 *)VbtHeader + VbtHeader->BdbOffset);
      PrintDebug(L"BDB Header @ VBT+0x%x (absolute 0x%lx)\n",
                 VbtHeader->BdbOffset, (EFI_PHYSICAL_ADDRESS)Bdb);
      PrintDebug(L"BDB Signature: \"%.*s\"\n", (int)sizeof(Bdb->Signature), Bdb->Signature);
      PrintDebug(L"BDB Version: %u, BDB Size: %u - 0x%x, HeaderSize: %u\n",
                 Bdb->Version, Bdb->BdbSize, Bdb->BdbSize, Bdb->HeaderSize);
      PrintDebug(L"BDB Child Device Version %u", ChildDeviceExpectedSize(Bdb->Version));

      UINT8 *BlockPtr = (UINT8 *)Bdb + Bdb->HeaderSize;
      UINT8 *BlockEnd = (UINT8 *)Bdb + Bdb->BdbSize;
      while (BlockPtr < BlockEnd)
      {
        UINT8 Id = *BlockPtr;
        UINT16 Size = *(UINT16 *)(BlockPtr + 1);
        PrintDebug(L"BDB Block: ID = %d Len=%d\n", Id, Size);
        BlockPtr += Size + 3;
      }

      UINT8 *gd_data = NULL;
      UINT16 gd_len = 0;

      gd_data = FindBdbBlockInplace(Bdb, BDB_GENERAL_DEFINITIONS_ID, &gd_len);
      if (!gd_data)
      {
        PrintError(L"General Definitions block not found\n");
      }
      else
      {
        PrintDebug(L"GeneralDefs block found at offset %ld (len %u)\n",
                   (UINT8 *)gd_data - ((UINT8 *)VbtHeader), gd_len);

        EFI_STATUS r = PatchLfp2_Inplace((UINT8 *)VbtHeader, VbtAddr, gd_data, gd_len);
        if (EFI_ERROR(r))
          PrintError(L"PatchLfp2_Inplace returned: %r\n", r);
        else
          PrintDebug(L"PatchLfp2_Inplace succeeded\n");
      }

      BDB_BLOCK *GdBlock = FindBdbBlock(Bdb, BDB_GENERAL_DEFINITIONS_ID);
      if (GdBlock)
      {
        BDB_GENERAL_DEFINITIONS *Defs = (BDB_GENERAL_DEFINITIONS *)GdBlock->Data;
        DumpGeneralDefinitions(Defs, GdBlock->Size);
        FreePool(GdBlock);
      }
      else
      {
        PrintError(L"General Definitions block not found!\n");
      }

      gBS->FreePool(Buffer);
    }
  }

  if (HandleBuffer != NULL)
    FreePool(HandleBuffer);

  if (!FoundIgd)
  {
    PrintError(L"No IGD device found!!\n");
    return EFI_NOT_FOUND;
  }

  return EFI_SUCCESS;
}

EFI_STATUS
EFIAPI
UefiMain(
    IN EFI_HANDLE ImageHandle,
    IN EFI_SYSTEM_TABLE *SystemTable)
{
  EFI_SIMPLE_FILE_SYSTEM_PROTOCOL *Volume;
  EFI_STATUS Status = EFI_SUCCESS;
  CHAR16 *LogFilePath = NULL;
  EFI_FILE_INFO *FileInfo;
  EFI_INPUT_KEY Key;

  mVbtPatchImage = ImageHandle;
  Status = gBS->HandleProtocol(mVbtPatchImage, &gEfiLoadedImageProtocolGuid, (VOID **)&mVbtPatchImageInfo);
  if (EFI_ERROR(Status))
  {
    PrintError(L"Unable to locate EFI_LOADED_IMAGE_PROTOCOL, aborting\n");
    goto Exit;
  }

  Status = gBS->HandleProtocol(mVbtPatchImageInfo->DeviceHandle, &gEfiSimpleFileSystemProtocolGuid, (VOID **)&Volume);
  if (EFI_ERROR(Status))
  {
    PrintError(L"Unable to find simple file system protocol (error: %r)\n", Status);
    goto Exit;
  }
  else
    PrintDebug(L"Found simple file system protocol\n");

  Status = Volume->OpenVolume(Volume, &mVolumeRoot);
  if (EFI_ERROR(Status))
  {
    PrintError(L"Unable to open volume (error: %r)\n", Status);
    goto Exit;
  }

  mEfiFilePath = PathCleanUpDirectories(ConvertDevicePathToText(mVbtPatchImageInfo->FilePath, FALSE, FALSE));
  if (mEfiFilePath == NULL)
  {
    PrintError(L"Unable to locate self-path, aborting\n");
    goto Exit;
  }

  ReadConfig();

  if (mLogToFile)
  {
    mLogToFile = FALSE;
    Status = GetFilenameInSameDirectory(mEfiFilePath, L"VbtPatch.log", (VOID **)&LogFilePath);
    if (!EFI_ERROR(Status))
    {
      PrintDebug(L"Clearing previous log file\n");
      FileDelete(mVolumeRoot, LogFilePath);

      Status = mVolumeRoot->Open(
          mVolumeRoot,
          &mLogFileHandle,
          LogFilePath,
          EFI_FILE_MODE_READ | EFI_FILE_MODE_WRITE | EFI_FILE_MODE_CREATE,
          0);
      if (!EFI_ERROR(Status))
      {
        FileInfo = GetFileInfo(mLogFileHandle);
        if (FileInfo != NULL)
        {
          /* Re-enable mLogToFile if it's not directory. */
          if ((FileInfo->Attribute & EFI_FILE_DIRECTORY) == 0)
          {
            mLogToFile = TRUE;
          }
          FreePool(FileInfo); /* ensure freed even if not NULL */
        }
        else
        {
          /* close handle and disable logging */
          mLogFileHandle->Close(mLogFileHandle);
          mLogFileHandle = NULL;
          mLogToFile = FALSE;
          PrintError(L"Unable to get log file info, disabling file logging\n");
        }
      }
      else
      {
        PrintError(L"Failed to open log file '%s': %r\n", LogFilePath, Status);
      }
      FreePool(LogFilePath);
    }
    else
    {
      PrintDebug(L"No log path resolved, skipping file logging\n");
    }
  }

  if (!mVerboseMode)
  {
    Status = gST->ConIn->ReadKeyStroke(gST->ConIn, &Key);
    if (!EFI_ERROR(Status) && (Key.UnicodeChar == L'v'))
    {
      mVerboseMode = TRUE;
    }
  }

  PrintDebug(L"VbtPatch 0.1\n");

  if (mVerboseMode)
  {
    PrintDebug(L"You are running in verbose mode, press Enter to continue\n");
    WaitForEnter(FALSE);
  }

  Status = HandleIgdVbt();
  if (EFI_ERROR(Status))
  {
    PrintError(L"HandleIgdVbt failed: %r\n", Status);
    goto Exit;
  }

  if (mLaunchEfi)
  {
    CHAR16 *BootPath = L"\\EFI\\BOOT\\BOOTX64.EFI";
    EFI_STATUS BootStatus;

    PrintDebug(L"Launching EFI: %s\n", BootPath);
    BootStatus = Launch(BootPath, NULL);
    if (EFI_ERROR(BootStatus))
      PrintError(L"Failed to launch EFI: %r\n", BootStatus);
  }

Exit:
  if (mEfiFilePath != NULL)
  {
    FreePool(mEfiFilePath);
  }

  if (mLogToFile)
  {
    if (mLogFileHandle != NULL)
    {
      mLogFileHandle->Close(mLogFileHandle);
    }
  }

  if (mVolumeRoot != NULL)
  {
    mVolumeRoot->Close(mVolumeRoot);
  }

  return EFI_SUCCESS;
}
