//
// SPDX-FileCopyrightText: 2026 Your name <your.email@example.com>
// SPDX-License-Identifier: AGPL-3.0-or-later
//
#define VOLUME_DOWN 17
#define ENV_INIT_CALL	0x4c4028a4
#define ENV_INIT_ADDR	0x4c44c1b4
#include <board_ops.h>
static void env_init(void) {
    ((void (*)(void))(ENV_INIT_ADDR | 1))();
}
 void spoof_lock_state(void) {
    uint32_t addr = 0;
	printf("Bootloader lock status spoofing enabled, applying patches.\n");

// AVB adds device state info to the kernel cmdline, but it keeps showing
     // "unlocked" even when we want it to say "locked". This patch forces
    // the cmdline to always use the "locked" string instead of checking
    // the actual device state.
    addr = SEARCH_PATTERN(LK_START, LK_END, 0xE92D, 0x4FF0, 0x4691, 0xF102);
    if (addr) {
        printf("Found AVB cmdline function at 0x%08X\n", addr);
       
        // Find where in libavb the device state is first fetched and then stored,
        // then Nop out the code that checks the actual device state.
        // This forces libavb to always use the "locked" string.
        NOP(addr + 0x9C, 4);
    }


    // Need to spoof the LKS_STATE as "locked" for certain scenarios, but still
    // return success so other parts of the system don't freak out. This makes
    // seccfg_get_lock_state always report lock_state=1 and return 2.
    addr = SEARCH_PATTERN(LK_START, LK_END, 0xB1D0, 0xB510, 0x4604, 0xF7FF, 0xFFDD);
    if (addr) {
        printf("Found seccfg_get_lock_state at 0x%08X\n", addr);
        PATCH_MEM(addr + 6, 
            0x2301,  // movs r3, #1
            0x6023,  // str r3, [r4, #0]
            0x2002,  // movs r0, #2
            0xbd10   // pop {r4, pc}
        );
    }
    // Force the secure boot state to ATTR_SBOOT_ENABLE (0x11). This controls whether
    // secure boot verification is enabled and is separate from the LKS_STATE above.
    // Setting it to 0x11 indicates secure boot is properly enabled.
    addr = SEARCH_PATTERN(LK_START, LK_END, 0xB510, 0x4604, 0x2001, 0xF7FF);
    if (addr) {
        printf("Found get_sboot_state at 0x%08X\n", addr);
        PATCH_MEM(addr,
            0x2311,  // movs r3, #0x11   - set value to 0x11
            0x6003,  // str r3, [r0,#0]  - store to *param_1
            0x2000,  // movs r0, #0      - return 0
            0x4770   // bx lr            - return
        );
    }
    // AVB verifies vbmeta public keys in two places: once for the main
    // vbmeta image (validate_vbmeta_public_key) and once for chained
    // vbmeta images (avb_safe_memcmp against the expected key). Both
    // reject the boot if the key doesn't match, causing the "Public key
    // used to sign data rejected" error. We patch both checks so any
    // key is accepted regardless.
    addr = SEARCH_PATTERN(LK_START, LK_END, 0x4FF0, 0xE92D, 0x5D44, 0xF2AD);
    if (addr) {
        printf("Found load_and_verify_vbmeta at 0x%08X\n", addr);

        // The chain key check first compares key lengths before calling
        // memcmp. If lengths differ, it skips memcmp and falls straight
        // to the error path. Change "cmp r2, r3" to "cmp r3, r3" so the
        // length check always succeeds, allowing execution to reach the
        // memcmp path (which we NOP below).
      //  PATCH_MEM(addr - 0x32C, 0x451B);

        // NOP the bne.w that rejects mismatched chained vbmeta keys,
        // falling through to the success path unconditionally.
     //   NOP(addr, 2);

        // Replace "cmp r3, #0" with "movs r3, #1" so key_is_trusted
        // is always nonzero and the following bne.w takes the success
        // branch.
       // PATCH_MEM(addr + 0x72, 0x2301);
    }
}




void board_early_init(void) {
    printf("Entering early init for tecno pova 2\n");
    uint32_t addr = 0;
    // Regardless of whether spoofing is enabled, we always need to
    // disable image authentication. The user may just be using this
    // custom LK to unlock their device, or they may be spoofing
    // where the locked state would enforce verification.
    //
    // Forcing get_vfy_policy to return 0 skips certificate
    // verification for all partitions and firmware images (boot,
    // recovery, dtbo, SCP, etc.) so the device can boot with
    // modified or unsigned images.
    addr = SEARCH_PATTERN(LK_START, LK_END, 0xB508, 0xF7FF, 0xFF75, 0xF3C0);
    if (addr) {
        printf("Found get_vfy_policy at 0x%08X\n", addr);
        FORCE_RETURN(addr, 0);
    }
    // Same idea but for download policy, forcing get_dl_policy to return
    // 0 ensures no partition is marked as download-forbidden, so flashing
    // via fastboot works for all partitions.
    addr = SEARCH_PATTERN(LK_START, LK_END, 0xB508, 0xF7FF, 0xFF6f, 0xF000);
    if (addr) {
        printf("Found get_dl_policy at 0x%08X\n", addr);
        FORCE_RETURN(addr, 0);
    }
    // This function handles certificate chain and hash verification for
    // modem-related images (md1rom, md3rom, etc.) during the modem loading
    // process. Same idea as above — force it to return 0 so modem images
    // can be loaded without passing signature verification.
    addr = SEARCH_PATTERN(LK_START, LK_END, 0xE92D, 0x41F0, 0x460A, 0x4604);
    if (addr) {
        printf("Found ccci_ld_md_sec_ptr_hdr_verify at 0x%08X\n", addr);
        FORCE_RETURN(addr, 0);
    }
	    // This function handles certificate chain and hash verification for
    // modem-related images (md1rom, md3rom, etc.) during the modem loading
    // process. Same idea as above — force it to return 0 so modem images
    // can be loaded without passing signature verification.
    addr = SEARCH_PATTERN(LK_START, LK_END, 0xE92D, 0x43F0, 0x460C, 0x4601);
    if (addr) {
        printf("Found ccci_ld_md_sec_image_verify at 0x%08X\n", addr);
        FORCE_RETURN(addr, 0);
    }
    // The environment area isn't initialized yet when board_early_init
    // runs, so any get_env calls would return NULL at this stage. We
    // hook a printf call in platform_init that runs right after env
    // initialization completes, it's a convenient entry point since
    // the call itself is non-essential and we need the env to be ready
    // before applying our lock state patches.
    addr = SEARCH_PATTERN(LK_START, LK_END, 0xF02F, 0xFDB2, 0x6823, 0x3B01);
    if (addr) {
        printf("Found env_init_done at 0x%08X\n", addr);
        PATCH_CALL(addr, (void*)spoof_lock_state, TARGET_THUMB);
    }
	//	PATCH_CALL(0x4c4028a4, (void*)spoof_lock_state, TARGET_THUMB);
	// When we spoof the lock state to appear "locked", fastboot starts rejecting 
    // commands with "not support on security" and "not allowed in locked state" 
    // errors. This is annoying since the device is actually unlocked underneath, 
    // the security checks are just being overly paranoid.
    //
    // This patch removes both security gates so fastboot commands work regardless
    // of what the spoofed lock state reports.
//0x4c426814
    addr = SEARCH_PATTERN(LK_START, LK_END, 0xE92D, 0x4FF0, 0xB0A7, 0xAA1C);
    if (addr) {
        printf("Found fastboot command processor at 0x%08X\n", addr);
        
        // NOP the error message calls
        NOP(addr + 0x6B8, 2);  // "not support on security" call   //0x4c426ecc ok
        NOP(addr + 0x6F8, 2);  // "not allowed in locked state" call  //4c426f0c ok
        
        // Jump directly to command handler
       PATCH_MEM(addr + 0x14A, //4C42695E
            0xE020 //4c426978
        );
		//4c426978
    }
			//custom_spoof_lock_state();
  	   // - Volume down → Fastboot
	    if (mtk_detect_key(1)) {
		printf("Found volume_down \n");
       // set_bootmode(BOOTMODE_FASTBOOT);
		FORCE_RETURN(0x4c419c48, 1);
    }
	 if (mtk_detect_key(0)) {
		printf("Found volume_up \n");
        set_bootmode(BOOTMODE_RECOVERY);
		//FORCE_RETURN(0x4c404550, 0);
   }
	    // Patch calling env_init to inject check_lock_spoof() right after 
    // manual initialization of environment
   // PATCH_CALL(ENV_INIT_CALL, (void*)hijack_env_init, TARGET_THUMB);



    fastboot_register("oem bldr_spoof", cmd_spoof_bootloader_lock, 0);
}

void board_late_init(void) {
    printf("Entering late init for tecno pova 2\n");
    uint32_t addr = 0;

    // Suppresses the bootloader unlock warning shown during boot on
    // unlocked devices. In addition to the visual warning, it also
    // introduces an unnecessary 5-second delay.
    // 
    // This patch get rid of the delay and the warning by forcing the
    // function that holds the logic to always return 0 and therefore
    // not executing the code that shows the warning.
    addr = SEARCH_PATTERN(LK_START, LK_END, 0xB510, 0xB082, 0x4C07, 0X4670, 0XF240);
    if (addr) {
        printf("Found orange_state_warning at 0x%08X\n", addr);
        FORCE_RETURN(addr, 0);
    }
    // Disables the dm-verity corruption warning shown during boot when
    // the device is unlocked. Without this patch, the user gets a scary
    // "Your device is corrupt" screen that waits for a power button
    // press and powers off after 5 seconds if ignored.
    addr = SEARCH_PATTERN(LK_START, LK_END, 0x2802, 0xD000, 0x4770, 0xB538);
    if (addr) {
        printf("Found dm_verity_corruption at 0x%08X\n", addr);
        FORCE_RETURN(addr, 0);
    }
        // Show the current boot mode on screen when not performing a normal boot.
        // This is standard behavior in many LK images, but not in this one by default.
        //
        // Displaying the boot mode can be helpful for developers, as it provides
        // immediate feedback and can prevent debugging headaches.
        show_bootmode(get_bootmode());

}
