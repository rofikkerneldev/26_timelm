#pragma once
/*
 * Board selection: build.sh passes -DBOARD_BERYLLIUM for the Poco F1
 * (xiaomi beryllium, SDM845); the default is sweet (SM7150).
 * Every value comes from the board's mainline/downstream device tree.
 */
#if defined(BOARD_BERYLLIUM)
#define BOARD_NAME		"beryllium"
/* reserved-memory cont_splash_mem@9d400000, simple-framebuffer 1080x2246 */
#define FB_BASE			0x9d400000UL
#define FB_W			1080
#define FB_H			2246
/* sdm845 imem@146bf000, restart_reason@65c */
#define IMEM_RESTART_REASON	0x146bf65cUL
#elif defined(BOARD_TIMELM)
#define BOARD_NAME		"timelm"
/* LG V60 (kona/SM8250): reserved memory@9c000000, framebuffer 1080x2445 a8r8g8b8 */
#define FB_BASE			0x9c000000UL
#define FB_W			1080
#define FB_H			2445
/* sm8250 imem@146bf000, restart_reason@65c */
#define IMEM_RESTART_REASON	0x146bf65cUL
/* Kona's armv8-timer node uses the standard PPIs: virt = PPI 11, hyp-phys = PPI 10. */
#define VTIMER_INTID		27
#define PTIMER_INTID		26
#else
#define BOARD_NAME		"sweet"
/* reserved-memory cont_splash_region@9c000000 */
#define FB_BASE			0x9c000000UL
#define FB_W			1080
#define FB_H			2400
/* qcom,msm-imem restart_reason@65c */
#define IMEM_RESTART_REASON	0x146aa65cUL
#endif

#define FB_STRIDE		(FB_W * 4)	/* a8r8g8b8, matches mainline simplefb */
#define FB_PHYS			FB_BASE

/* Same on SM7150 and SDM845 */
#define PSHOLD			0x0c264000UL
#define GICD_BASE		0x17a00000UL
#define GICR_BASE		0x17a60000UL
#define GICR_SIZE		0x100000UL
#define UFS_BASE		0x01d84000UL	/* ufshc@1d84000 */
