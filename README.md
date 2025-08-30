# VbtPatch – EFI application for LFP2 modification

## Overview 
VbtPatch is a project designed to disable the faulty panel of the Video BIOS Table (VBT) of Intel GPUs on UEFI level.

Although this issue does not occur on every device, it doesn't function properly on the Linux side due to its [incorrect implementation](https://wiki.archlinux.org/title/Intel_graphics#Freeze_after_wake_from_sleep/suspend_with_Raptor_Lake_and_Alder_Lake-P) on some newer HP Gen12 *(12, 13 and 14th series CPUs)* laptops.

A BIOS update/modification is required for a permanent fix, but since HP doesn't provide this and almost all of its laptops have Intel Boot Guard, it has become impossible.

This application can fix this by patching it at the UEFI level (And running before the kernel), 

## Why VbtPatch?

Existing workaround:
 - The Linux kernel supports the parameter `i915.vbt_firmware`, which allows supplying a patched VBT blob to the driver.

- But... this requires modifying the initramfs, which is painful, especially on immutable distros (e.g. Fedora Silverblue, NixOS) or when kernel updates overwrite the initramfs.

- Additionally, there is no such parameter in the new [Xe](https://docs.kernel.org/gpu/xe/index.html) kernel driver, so you will have to forcefully compile a custom kernel.

Advantages:

- Runs entirely at the UEFI level, before any operating system is loaded.

- It works on all operating systems (Linux, Windows, BSD) based on Intel Graphics Drivers.

- Requires no kernel patching, initramfs regeneration, or OS specific configuration.

Disadvantages:

- On an OSes with Secure Boot enabled requires manual signing, which is a difficult process.
- May seem complicated for users unfamiliar with UEFI; it's not intended for everyone 😶.
- There is no guarantee that it will work on every laptop; at least it works successfully on my laptop (Victus fa-1010nt).

## Build

1. Clone [EDK2](https://github.com/tianocore/edk2) and setup the build environment.
```sh
git clone https://github.com/tianocore/edk2.git
cd edk2
source edksetup.sh
```
2. Place the `VbtPatchPkg/` folder inside `edk2/`.

3. Build with:
```sh
build -a X64 -t GCC -p VbtPatchPkg/VbtPatchPkg.dsc
```

4. The compiled EFI binary will be at:
```sh
Build/VbtPatchPkg/DEBUG_GCC/X64/VbtPatch.efi
```

## Usage

Copy the following files to your EFI Partition (ESP), e.g. `/boot/efi/`:
```
EFI/
  GRUB/
  Microsoft/
  BOOT/
    BOOTX64.EFI   ← (your GRUB or OS bootloader)    
grub/
VbtPatch.efi
VbtPatch.ini
```

2. Configure `VbtPatch.ini`:

```ini
[config]
verbose=1     ; Enable debug logging to console
logfile=1     ; Write logs to VbtPatch.log in the EFI partition
launch_efi=1  ; Launch \EFI\BOOT\BOOTX64.EFI after patching
```

3. Add VbtPatch.efi as a boot option in your BIOS (e.g. via `efibootmgr` on Linux):
```sh
sudo efibootmgr -c -d /dev/nvme0n1 -p 1 -L "VbtPatch" -l 'VbtPatch.efi'
```
4. On boot, VbtPatch will:

- Patch the Intel VBT in memory

- Disable the faulty `DEVICE_HANDLE_LFP2`

- Recalculate checksum

- Optionally chainload `\EFI\BOOT\BOOTX64.EFI`

Logs will be available in `VbtPatch.log` if `logfile=1` is enabled.

## How It Works

1. VbtPatch locates the Intel Video BIOS Table (VBT) in physical memory, normally parsed by the graphics driver (see `intel_bios_get_vbt`).
2. It searches in the Child Device Table for the `DEVICE_HANDLE_LFP2` entry.
3. If found, it sets the `device_type` value of LFP2 to 0 (which disables).
```c
  /* parse_general_definitions -- drm/i915/display/intel_bios.c */
  for (i = 0; i < child_device_num; i++) {
    child = child_device_ptr(defs, i);
    if (!child->device_type)
      continue; // simply if device_type doesn't exist, it doesn't add it to the list
			
    list_add_tail(&devdata->node, &display->vbt.display_devices);
```
4. VBT checksum is recalculated to maintain table integrity (not required for i915, but necessary for compatibility with Windows).
5. The modified table is written back directly to memory.
6. If specified, loads `/EFI/BOOT/BOOTX64.EFI` in the same partition.

## Technical Details

`DEVICE_HANDLE_LFP2`: It represents the second embedded display panel (Local Flat Panel 2). On some HP laptops, this entry is included even if the second panel is not physically included.

Problem: The `i915` driver interprets it as a valid display, leading to incorrect initialization and suspend/resume failures.

Solution: Setting the `device_type` value of LFP2 to `0x00` disables the entry. This is consistent with Intel’s VBT semantics.

## My Journey

Initially, I was already able to handle it with i915.vbt_firmware, but when I started using NixOS, I realized how bad it's to hardcode files into the initramfs. I wondered if we could change this at the UEFI level and avoid messing with the kernel. So... I wrote an application that randomly corrupted the VBT offset at the UEFI level, and I saw that it really did get corrupted on the Linux side. If we can modify the memory this way and break the VBT, we can also modify it the same way and fix it, right?

And that's how it all began.

To be honest, making VbtPatch was a crazy journey... This was my first time working with the Linux graphics kernel and also my first UEFI application, and while the idea seemed great, it was quite a challenge for someone like me 😐 I had to research the inner workings of UEFI, Intel VBT structures, and how the i915 driver went haywire with LFP2 entries.

I learned a lot from UEFISeven, a similar project where I used its code, I also learned how to parse VBT thanks to the igt-gpu-tools project.

I'm grateful you've read this far without getting bored. I hope you never have to own an HP laptop like this...

## Special Thanks

- [UEFISeven](https://github.com/manatails/uefiseven): For understanding the UEFI structure and the Filesystem code I use.

- [igd-gpu-tools](https://gitlab.freedesktop.org/drm/igt-gpu-tools): For describes the entire VBT structure and parsing.

- Algernop, for giving the solution method that I used for months.
## License

VbtPatch is released under the GNU General Public License v3.0 (GPL-3.0).
That means you’re free to use, modify, and redistribute it, as long as you keep it under the same license.

Check out the full license here: https://www.gnu.org/licenses/gpl-3.0.en.html