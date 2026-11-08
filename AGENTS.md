# Working on ios-beryllium (fork of ios-sweet)

- Do NOT add a `Co-Authored-By: dipa-studio` (or any other co-author) trailer to commits in this fork; that rule in NOTES.md is upstream ios-sweet's. Credit upstream in README.md only.

- Read `NOTES.md` before starting; it contains the project goal, hardware facts,
  current blocker, local artifact locations and the next concrete action.
- The user switches agents frequently. Update the active handoff in `NOTES.md`
  after each milestone and before stopping. Record commits, CI run IDs, exact
  build/boot results and unfinished work. Distinguish observations from guesses.
- Commit completed changes. Use `gh` for GitHub Actions kernel builds and logs.
  Local single-file cross-compiles are useful before spending a CI run.
- Device bring-up uses temporary `fastboot boot` images. Preserve the Android
  installation and partition backups. The user approved (2026-10-15) using
  internal UFS for iOS and said Android may be deleted: the iOS root goes
  into the existing `userdata` partition (no GPT changes). Keep bootloaders,
  recovery, modem, persist and the backups intact, and confirm each
  destructive step with the user before running it.
- Keep device dumps, serial numbers and downloaded Apple artifacts out of git.

## timelm (LG V60) notes

- Timelm reference path: `/home/rofikkernel/xnu/TIMELM-IOS26.md`; hardware map: `~/LGV60_HW_DETAIL/`. Board is runtime-detected from ADT compatible `lg,timelm` (SWEET machine config, patch `xnu/patches-12377/1200-*`).
- On timelm the iOS root is the **`ios` GPT partition** (`ufsroot=ios`, `rd=ufsroot0`), NOT `userdata` — userdata is Android on this phone, do not overwrite it.
- **Upload test builds:**
  - **Pixeldrain** for files < 100 MB (boot images, kernels, ADTs, payloads): `pd upload boot_ios_test<N>.img` (`~/go/bin/pd`). Prints a share URL.
  - **Gofile** for big files (rootfs `.simg`, multi-GB) — avoid unless necessary (the iOS rootfs is already flashed; prefer reusing it): `python3 ~/gofile/gofile_upload.py FILE` or `~/bin/gofile.sh FILE`.
  - Name test images `boot_ios_test<N>.img` / `timelm-ios26-boot-<tag>.img` so flash logs can be matched to a build. Never upload Apple-IPSW-derived content (IPSW, rootfs) to public links — kernels/enxerto boot images are fine.
- CI trigger without a PR: `gh workflow run xnu.yml -R rofikkerneldev/26_timelm --ref ios26` (or push the `ios26` branch — push trigger covers it). `gh run download -R rofikkerneldev/26_timelm -n xnu-kernel` for `kernel.development.sweet` (artifacts need gh auth).
- Boot test: `fastboot boot ~/work/ios26-timelm/timelm-ios26-boot.img` (built by `~/work/ios26-timelm/mkboot-timelm.sh mach.development <adt>`). Kernel log lands on the framebuffer console (`serial=3`); if it hangs on USB, drop `sweetusb=2` (timelm SNPS HS-PHY @0x88e3000, not beryllium QUSB2).

## Access paths to the device (beyond adb recovery)

- **Ubuntu arm64 userspace on the phone** (`/dev/block/by-name/linux` partition): the V60 can boot a Linux arm64 system; SSH in with
  `ssh -p 2222 ubuntu@127.0.0.1` (pass `ubuntu`) — full root shell on-device to inspect/edit the `ios` partition directly (mount the HFSX, edit launchd plists, drop payloads) — much better than adb recovery for rootfs work.
- **iOS rootfs debug/payload approach**: to get framebuffer console + logging deeper into the boot, a jailbreak-style payload can be pushed into the iOS rootfs (jailbreak tools / dropbear inside iOS show the framebuffer and let you debug from inside). Jailbreak hooks can be added to the root image via the Renegade/renegade-rs tools stage (`tools/renegade-rs ... --tools berga-tools.zip`), or dropped onto the `ios` partition directly through the Ubuntu-SSH path above.
- fastboot remains the boot path (`fastboot boot boot_ios_test*.img`); `adb` only helps when the phone runs Android/TWRP.
