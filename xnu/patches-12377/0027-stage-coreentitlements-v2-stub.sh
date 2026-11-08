#!/bin/bash
# Build xnu-12377 for SWEET without a KDK. libkern/amfi/amfi.h includes <CoreEntitlements/V2/API.h> and
# <CoreEntitlements/V2/Kernel.h>, which are not in the open-source tree (dxb copies them from the KDK in
# patches/26.0/00_setup_coreentitlements.sh). Every xnu call through the V2 API (libCoreEntitlements->...) is
# under CODE_SIGNING_MONITOR or PMAP_CS_INCLUDE_CODE_SIGNING, both off for SWEET, and SWEET loads no AMFI kext
# that would register an implementation. So only the type names are needed: opaque structs and the return enum.
# When the real headers are present (KDK build) this script does nothing.
set -euo pipefail

[[ "${MACHINE_CONFIG:-}" == SWEET ]] || exit 0
[[ -f libkern/libkern/amfi/amfi.h ]] || exit 1
v2=EXTERNAL_HEADERS/CoreEntitlements/V2
if [[ -f "$v2/API.h" && -f "$v2/Kernel.h" ]]; then
    echo "CoreEntitlements V2 headers present (KDK): no stub"
    exit 0
fi
mkdir -p "$v2"

cat > "$v2/API.h" <<'H'
/* SWEET stand-in for the KDK-only CoreEntitlements V2 API: type names only (no implementation exists in a
 * SWEET kernel; every caller is compiled out with CODE_SIGNING_MONITOR / PMAP_CS off). */
#ifndef _SWEET_COREENTITLEMENTS_V2_API_H
#define _SWEET_COREENTITLEMENTS_V2_API_H

#include <CoreEntitlements/CoreEntitlements.h>

typedef enum {
	kCEReturnSuccess = 0,
	kCEReturnError,
} CEReturn_t;

typedef enum {
	kCEContextTypeInvalid = 0,
	kCEContextTypeProvisioningProfile,
	kCEContextTypeProvisioningProfileEntitlements,
} CEContextType_t;

typedef struct CEContext CEContext_t;
typedef struct CEElement CEElement_t;
typedef CEBuffer CEBuffer_t;                    /* CEBuffer: CoreEntitlements/Runtime.h (V1) */

#endif /* _SWEET_COREENTITLEMENTS_V2_API_H */
H

cat > "$v2/Kernel.h" <<'H'
/* SWEET stand-in for the KDK-only CoreEntitlements V2 kernel table (see API.h). Opaque: nothing in a SWEET
 * kernel registers or calls it. */
#ifndef _SWEET_COREENTITLEMENTS_V2_KERNEL_H
#define _SWEET_COREENTITLEMENTS_V2_KERNEL_H

#include <CoreEntitlements/V2/API.h>

typedef struct CEKernelAPI CEKernelAPI_t;

#endif /* _SWEET_COREENTITLEMENTS_V2_KERNEL_H */
H
echo "Staged CoreEntitlements V2 type stubs for SWEET (no KDK)"

# --- additional KDK-only headers the no-KDK build needs (inlined) ---
# TrustCache/API.h (amfi.h, pmap_cs.h), CodeSignature/Entitlements.h (kern_exec, necp_client),
# CoreEntitlements V1 tree + img4 (TrustCache deps). Only written when absent (KDK wins).
if [ ! -f "EXTERNAL_HEADERS/TrustCache/API.h" ]; then
    mkdir -p "EXTERNAL_HEADERS/TrustCache"
    cat > "EXTERNAL_HEADERS/TrustCache/API.h" <<'STAGEEOF'
#ifndef libTrustCache_API_h
#define libTrustCache_API_h

#include <sys/cdefs.h>
__BEGIN_DECLS

#include <stdint.h>
#include <stdbool.h>
#include <img4/firmware.h>
#include <TrustCache/RawTypes.h>
#include <TrustCache/Types.h>
#include <TrustCache/TypesConfig.h>
#include <TrustCache/Return.h>

/**
 * NOTE: This library does not enforce any concurrency by itself. To be safe in a multi-threaded
 * environment, the caller must manually enforce concurrency on the runtime data structure as
 * otherwise the library is susceptible to memory corruption from race conditions.
 */

/**
 * Initialize a runtime to the default values.
 *
 * If the system supports read-only segments, and the runtime is allocated within the read-only
 * segment, then this function needs to be called before the segment is enforced to be read-only.
 * For more information, please look at <TrustCache/Types.h>.
 */
static inline void
trustCacheInitializeRuntime(TrustCacheRuntime_t *runtime,
                            TrustCacheMutableRuntime_t *mutableRT,
                            bool allowSecondStaticTC,
                            bool allowEngineeringTC,
                            bool allowLegacyTC,
                            const img4_runtime_t *image4RT)
{
    /* Zero out everything */
    memset(runtime, 0, sizeof(*runtime));
    memset(mutableRT, 0, sizeof(*mutableRT));

    /* Set the mutable runtime pointer */
    runtime->mutableRT = mutableRT;

    /* Setup trust cache type permissions */
    runtime->allowSecondStaticTC = allowSecondStaticTC;
    runtime->allowEngineeringTC = allowEngineeringTC;
    runtime->allowLegacyTC = allowLegacyTC;

    /* Set the image4 runtime */
    runtime->image4RT = image4RT;
}

/**
 * Construct a trust cache object from some module bytes. The module is validated for
 * correctness before being returned.
 */
TCReturn_t
trustCacheConstructInvalid(TrustCache_t *trustCache,
                           const uint8_t *moduleAddr,
                           size_t moduleSize);

/**
 * Check the runtime for a trust cache which matches a particular UUID. Since we do
 * not allow trust caches with duplocate UUIDs, there can only ever be a single trust
 * cache with a particular UUID within the runtime.
 */
TCReturn_t
trustCacheCheckRuntimeForUUID(const TrustCacheRuntime_t *runtime,
                              const uint8_t checkUUID[kUUIDSize],
                              const TrustCache_t **trustCacheRet);

/**
 * Add a trust cache module directly to the runtime. This function is used to add modules which
 * don't need to be separately authenticated. Currently, the only trust cache types which can be
 * used with this function are static and engineering trust caches.
 *
 * If the system supports read-only segments, and the runtime is allocated within the read-only
 * segment, then this function needs to be called before the segment is enforced to be read-only.
 * For more information, please look at <TrustCache/Types.h>.
 */
TCReturn_t
trustCacheLoadModule(TrustCacheRuntime_t *runtime,
                     const TCType_t type,
                     TrustCache_t *trustCache,
                     const uintptr_t dataAddr,
                     const size_t dataSize);

/**
 * Load a trust cache onto the system. This function validates the trust cache for a proper
 * signature and adds it to the runtime.
 *
 * Both the payload and the manifest must be provided and they will be validated as image4
 * objects.
 */
TCReturn_t
trustCacheLoad(TrustCacheRuntime_t *runtime,
               TCType_t type,
               TrustCache_t *trustCache,
               const uintptr_t payloadAddr,
               const size_t payloadSize,
               const uintptr_t manifestAddr,
               const size_t manifestSize);

/**
 * Extract an image4 artifact from an image4 file or an image4 payload and extract the
 * trust cache module embedded within it. The module is validated for correctness
 * before being returned, however the image4 signature is not verified.
 *
 * The returned trust cache object is marked with an invalid type.
 */
TCReturn_t
trustCacheExtractModule(TrustCache_t *trustCache,
                        const uint8_t *dataAddr,
                        size_t dataSize);

/**
 * Query a  trust cache for a particular CDHash. The returned token can then be used to
 * query further attributes from the matched entry.
 */
TCReturn_t
trustCacheQuery(const TrustCacheRuntime_t *runtime,
                TCQueryType_t queryType,
                const uint8_t CDHash[kTCEntryHashSize],
                TrustCacheQueryToken_t *queryToken);

/**
 * Get the module bytes backng a trust cache object. The environment may have chosen
 * to allocate the module bytes within read-only memory, so the bytes returned may
 * not be mutable.
 */
TCReturn_t
trustCacheGetModule(const TrustCache_t *trustCache,
                    const uint8_t **moduleAddrRet,
                    size_t *moduleSizeRet);

/**
 * Get the UUID of the trust cache module represented by the wrapped trust cache object.
 */
TCReturn_t
trustCacheGetUUID(const TrustCache_t *trustCache,
                  uint8_t returnUUID[kUUIDSize]);

/**
 * Get the capabilities of a trust cache. This function can be used to query which fields a given
 * trust cache supports.
 *
 * The fields which are supported are based on the version of the trust cache module.
 */
TCReturn_t
trustCacheGetCapabilities(const TrustCache_t *trustCache,
                          TCCapabilities_t *capabilities);

/**
 * Acquire the trust cache type for a query token.
 */
TCReturn_t
trustCacheQueryGetTCType(const TrustCacheQueryToken_t *queryToken,
                         TCType_t *typeRet);

/**
 * Acquire the capabilities of the trust cache through a query token.
 */
TCReturn_t
trustCacheQueryGetCapabilities(const TrustCacheQueryToken_t *queryToken,
                               TCCapabilities_t *capabilities);

/**
 * Acquire the hash type for the CDHash through a query token.
 */
TCReturn_t
trustCacheQueryGetHashType(const TrustCacheQueryToken_t *queryToken,
                           uint8_t *hashTypeRet);

/**
 * Acquire the flags for a trust cache entry through a query token.
 */
TCReturn_t
trustCacheQueryGetFlags(const TrustCacheQueryToken_t *queryToken,
                        uint64_t *flagsRet);

/**
 * Acquire the constraint category for a trust cache entry through a query token.
 */
TCReturn_t
trustCacheQueryGetConstraintCategory(const TrustCacheQueryToken_t *queryToken,
                                     uint8_t *constraintCategoryRet);

__END_DECLS
#endif /* libTrustCache_API_h */
STAGEEOF
    echo "Staged TrustCache/API.h (no KDK)"
fi
if [ ! -f "EXTERNAL_HEADERS/TrustCache/RawTypes.h" ]; then
    mkdir -p "EXTERNAL_HEADERS/TrustCache"
    cat > "EXTERNAL_HEADERS/TrustCache/RawTypes.h" <<'STAGEEOF'
#ifndef libTrustCache_RawTypes_h
#define libTrustCache_RawTypes_h

#include <sys/cdefs.h>
__BEGIN_DECLS

#include <stdint.h>
#include <corecrypto/ccsha1.h>

/*
 * CDHashes in the trust cache are always truncated to the length of a SHA1 hash.
 */
#define kTCEntryHashSize CCSHA1_OUTPUT_SIZE

/* UUIDs are always 16 bytes */
#define kUUIDSize 16

/* Versions supported by the library */
enum {
    kTCVersion0 = 0x0,
    kTCVersion1 = 0x1,
    kTCVersion2 = 0x2,

    kTCVersionTotal,
};

/* Flags for the trust cache look ups */
enum {
    kTCFlagAMFID = 0x01,
    kTCFlagANEModel = 0x02,
};

typedef struct _TrustCacheModuleBase {
    /* The version for this trust cache module */
    uint32_t version;
} __attribute__((packed)) TrustCacheModuleBase_t;

#pragma mark Trust Cache Version 0

typedef uint8_t TrustCacheEntry0_t[kTCEntryHashSize];

typedef struct _TrustCacheModule0 {
    /* Must be 0 */
    uint32_t version;

    /* ID which uniquely identifies the trust cache */
    uint8_t uuid[kUUIDSize];

    /* The number of entries present in the trust cache */
    uint32_t numEntries;

    /* Dynamic data containing all the entries */
    TrustCacheEntry0_t entries[0];
} __attribute__((packed)) TrustCacheModule0_t;

#pragma mark Trust Cache Version 1

typedef struct _TrustCacheEntry1 {
    uint8_t CDHash[kTCEntryHashSize];
    uint8_t hashType;
    uint8_t flags;
} __attribute__((packed)) TrustCacheEntry1_t;

typedef struct _TrustCacheModule1 {
    /* Must be 1 */
    uint32_t version;

    /* ID which uniquely identifies the trust cache */
    uint8_t uuid[kUUIDSize];

    /* The number of entries present in the trust cache */
    uint32_t numEntries;

    /* Dynamic data containing all the entries */
    TrustCacheEntry1_t entries[0];
} __attribute__((packed)) TrustCacheModule1_t;

#pragma mark Trust Cache Version 2

typedef struct _TrustCacheEntry2 {
    uint8_t CDHash[kTCEntryHashSize];
    uint8_t hashType;
    uint8_t flags;
    uint8_t constraintCategory;
    uint8_t reserved0;
} __attribute__((packed)) TrustCacheEntry2_t;

typedef struct _TrustCacheModule2 {
    /* Must be 2 */
    uint32_t version;

    /* ID which uniquely identifies the trust cache */
    uint8_t uuid[kUUIDSize];

    /* The number of entries present in the trust cache */
    uint32_t numEntries;

    /* Dynamic data containing all the entries */
    TrustCacheEntry2_t entries[0];
} __attribute__((packed)) TrustCacheModule2_t;

__END_DECLS
#endif /* libTrustCache_RawTypes_h */
STAGEEOF
    echo "Staged TrustCache/RawTypes.h (no KDK)"
fi
if [ ! -f "EXTERNAL_HEADERS/TrustCache/Return.h" ]; then
    mkdir -p "EXTERNAL_HEADERS/TrustCache"
    cat > "EXTERNAL_HEADERS/TrustCache/Return.h" <<'STAGEEOF'
#ifndef libTrustCache_Return_h
#define libTrustCache_Return_h

#include <sys/cdefs.h>
__BEGIN_DECLS

#include <stdint.h>

/* Components which can return information from the library */
enum {
    kTCComponentLoadModule = 0x00,
    kTCComponentLoad = 0x01,
    kTCComponentImage4Validate = 0x02,
    kTCComponentImage4Callback = 0x03,
    kTCComponentConstructInvalid = 0x04,
    kTCComponentCheckRuntimeForUUID = 0x05,
    kTCComponentExtractModule = 0x06,
    kTCComponentGetUUID = 0x07,
    kTCComponentGetModule = 0x08,

    /* Query Functions */
    kTCComponentQuery = 0x10,
    kTCComponentQueryChain = 0x11,
    kTCComponentQueryRuntime = 0x12,
    kTCComponentQueryTCType = 0x13,
    kTCComponentQueryHashType = 0x14,
    kTCComponentQueryFlags = 0x15,
    kTCComponentQueryConstraintCategory = 0x16,

    /* Module based */
    kTCComponentQueryModule = 0x40,
    kTCComponentValidateModule = 0x41,
    kTCComponentQueryModule0 = 0x42,
    kTCComponentValidateModule0 = 0x43,
    kTCComponentQueryModule1 = 0x44,
    kTCComponentValidateModule1 = 0x45,
    kTCComponentQueryModule2 = 0x46,
    kTCComponentValidateModule2 = 0x47,
    kTCComponentModuleCapabilities = 0x48,

    /* Other functions which can return a value */
    kTCComponentLinkedListAddHead = 0x80,
    kTCComponentLinkedListRemove = 0x81,
    kTCComponentExtractImage4Payload = 0x82,

    /* Cannot exceed this value */
    kTCComponentTotal = 0xFF,
};

/* Error types which can be returned from the library */
enum {
    kTCReturnSuccess = 0x00,

    /* Generic error condition - avoid using this */
    kTCReturnError = 0x01,

    /* Specific error conditions */
    kTCReturnOverflow = 0x20,
    kTCReturnUnsupported = 0x21,
    kTCReturnInvalidModule = 0x22,
    kTCReturnDuplicate = 0x23,
    kTCReturnNotFound = 0x24,
    kTCReturnInvalidArguments = 0x25,
    kTCReturnInsufficientLength = 0x26,
    kTCReturnNotPermitted = 0x27,
    kTCReturnLinkedListCorrupted = 0x28,

    /* Image 4 return errors */
    kTCReturnImage4Expired = 0xA0,
    kTCReturnImage4UnknownFormat = 0xA1,
    kTCReturnImage4WrongObject = 0xA2,
    kTCReturnImage4WrongCrypto = 0xA3,
    kTCReturnImage4ManifestViolation = 0xA4,
    kTCReturnImage4PayloadViolation = 0xA5,
    kTCReturnImage4PermissionDenied = 0xA6,
    kTCReturnImage4NoChipAvailable = 0xA7,
    kTCReturnImage4NoNonceAvailable = 0xA8,
    kTCReturnImage4NoDeviceAvailable = 0xA9,
    kTCReturnImage4DecodeError = 0xAA,
    kTCReturnImage4UnknownError = 0xAF,

    /* Cannot exceed this value */
    kTCReturnTotal = 0xFF
};

typedef struct _TCReturn {
    union {
        /* Raw 32 bit representation of the return code */
        uint32_t rawValue;

        /* Formatted representation of the return code */
        struct {
            /* Component of the library which is returning the code */
            uint8_t component;

            /* Error code which is being returned */
            uint8_t error;

            /* Unique error path within the component */
            uint16_t uniqueError;
        } __attribute__((packed));
    } __attribute__((packed));
} __attribute__((packed)) TCReturn_t;

/* Ensure the size of the structure remains as expected */
_Static_assert(sizeof(TCReturn_t) == sizeof(uint32_t), "TCReturn_t is not 32 bits large");

static inline TCReturn_t
buildTCRet(uint8_t component,
           uint8_t error,
           uint16_t uniqueError)
{
    TCReturn_t ret = {
        .component = component,
        .error = error,
        .uniqueError = uniqueError
    };

    return ret;
}

__END_DECLS
#endif /* libTrustCache_Return_h */
STAGEEOF
    echo "Staged TrustCache/Return.h (no KDK)"
fi
if [ ! -f "EXTERNAL_HEADERS/TrustCache/Types.h" ]; then
    mkdir -p "EXTERNAL_HEADERS/TrustCache"
    cat > "EXTERNAL_HEADERS/TrustCache/Types.h" <<'STAGEEOF'
#ifndef libTrustCache_Types_h
#define libTrustCache_Types_h

#include <sys/cdefs.h>
__BEGIN_DECLS

#include <stdint.h>
#include <img4/firmware.h>
#include <TrustCache/RawTypes.h>

typedef uint8_t TCType_t;
enum {
    /*
     * These types of trust caches are always loaded as modules. Their validation
     * is done externally by upper-level software.
     *
     * Static trust caches are bundled with the operating system and are the primary
     * method of denoting platform trust. Engineering trust caches are similar to
     * static trust caches except that they can be created by engineers at their
     * desk as a root for a static trust cache. Legacy trust caches are image3 signed
     * modules. This library does not support validating image3 signatures, so it
     * accepts the trust caches only as direct modules. These are still considered
     * loadable trust caches.
     */
    kTCTypeStatic = 0x00,
    kTCTypeEngineering = 0x01,
    kTCTypeLegacy = 0x02,

    /*
     * Do NOT change the order of the types listed here. This header is shared across
     * a variety of projects and they update at different cadences. Adding a new type
     * requires appending to the end of the enumeration, instead of insertion in the
     * middle somewhere.
     */

    /*
     * Type: Personalized
     * These are engineering roots which are only ever valid for development devices.
     * These can be created by engineers at their desks for testing software.
     */
    kTCTypeDTRS = 0x03,

    /*
     * Type: Personalized
     * These are loadable trust caches which are viable for all kinds of devices and
     * can be used for testing, but also for shipping code in production devices.
     */
    kTCTypeLTRS = 0x04,

    /*
     * Type: Personalized
     * Used by disk images which are used to supply platform code for a number of use
     * cases, including the multidude of disk images supplied for engineering use-cases
     * such as the factoey disk image.
     */
    kTCTypePersonalizedDiskImage = 0x05,

    /*
     * Type: Categorized
     * Developer disk images which are personalized per device. These have a different
     * tag than standard loadable trust caches and helps differentiate them. However,
     * these were never productionized and are for all purposes, retired.
     */
    kTCTypeDeveloperDiskImage = 0x06,

    /*
     * Type: Personalized
     * These trust caches are similar to a personalized LTRS trust cache type except
     * they are personalized against a long lived nonce, allowing these to remain
     * useable across reboots of the system.
     */
    kTCTypeLTRSWithDDINonce = 0x07,

    /*
     * Type: Personalized
     * These trust cache types are used to authenticate code shipped in Cryptexes for
     * security research devices. Outside of the SRD, these are also used in some data
     * center use cases which deploy code through Cryptexes.
     */
    kTCTypeCryptex = 0x08,

    /*
     * Type: Personalized (against supplemental root)
     * These are special trust caches which validate against a supplemental root beyond
     * Tatsu. These are only meant for special deployments within some data centers.
     *
     * NOTE: This type is deprecated in favor of the newer Supplemental Persistent
     * and Supplemental Ephemeral types.
     */
    kTCTypeEphemeralCryptex = 0x09,

    /*
     * Type: Global
     * OTA updates ship an update brain to assist with the OS update. The brain is some
     * code with platform privileges which can do whatever the current OS needs it to do
     * in order to update the system.
     */
    kTCTypeUpdateBrain = 0x0A,

    /*
     * Type: Global
     * Trust caches which are loaded by the Install Assistant on macOS in order to help
     * with installing macOS.
     */
    kTCTypeInstallAssistant = 0x0B,

    /*
     * Type: Global
     * These are used by macOS systems to ship a bootability brain. The bootability brain
     * is a piece of code which helps determine if macOS systems of a different version
     * are bootable or not. The brain is useful because the logic for determining that a
     * system is bootable or not differs with each release.
     */
    kTCTypeBootabilityBrain = 0x0C,

    /*
     * Type: Personalized (against Cryptex 1 Boot/Preboot environments)
     * These trust cache types are used by SPLAT at different stages of the boot pipeline
     * for loading code responsible for system boot up, such as the shared cache.
     *
     * The personalization uses a Cryptex1 nonce domain, which is embedded within the
     * manifest itself.
     */
    kTCTypeCryptex1BootOS = 0x0D,
    kTCTypeCryptex1BootApp = 0x0E,
    kTCTypeCryptex1PreBootApp = 0x0F,

    /*
     * Type: Global
     * These are disk images which are globally signed against the FF00 chip environment.
     * They are used when disk images want to supply code for devices across the fleet
     * without requiring individual personalization for each.
     *
     * The developer disk image is supplied through this mechanism as well, as of January
     * 5th, 2022.
     */
    kTCTypeGlobalDiskImage = 0x10,

    /*
     * Type: Personalized (Cryptex1 mobile asset brain)
     * The mobile asset brain contains the core logic for mobileassetd, which is a system
     * daemon responsible for downloading and maintaining assets on the device. The brain
     * is meant to be back-deployable, which is what the trust cache helps with.
     *
     * The personalization uses a Cryptex1 nonce domain, which is embedded within the
     * manifest itself.
     */
    kTCTypeMobileAssetBrain = 0x11,

    /*
     * Type: Personalized (Cryptex1 boot reduced)
     * Safari is backported to older builds. Since Safari is now moving to a SPLAT based
     * mount volume, we need to support loading a trust cache which is used to mount and
     * run Safari from the future.
     *
     * The personalization uses a Cryptex1 nonce domain, which is embedded within the
     * manifest itself.
     */
    kTCTypeSafariDownlevel = 0x12,

    /*
     * Type: Personalized (Cryptex 1 Preboot)
     * This trust cache type is used for the semi-SPLAT use-case for loading the new dyld
     * shared cache onto the platform, along with some other system libraries. This is
     * only required for macOS.
     *
     * The personalization uses a Cryptex1 nonce domain, which is embedded within the
     * manifest itself.
     */
    kTCTypeCryptex1PreBootOS = 0x13,

    /*
     * Type: Personalized (Supplemental Root)
     * Persistent trust caches which are signed by an authority different from Tatsu.
     * These are only required for deployment on darwinOS platforms.
     */
    kTCTypeSupplementalPersistent = 0x14,

    /*
     * Type: Personalized (Supplemental Root)
     * Ephemeral trust caches which are signed by an authority different from Tatsu.
     * These are only required for deployment on darwinOS platforms.
     */
    kTCTypeSupplementalEphemeral = 0x15,

    /*
     * Type: Personalized (Cryptex1 Generic)
     * This type can be used by the assortment of PDIs we ship. Each PDI train can opt
     * into allocating a Cryptex1 sub-type for itself, and then ship on the OS being
     * signed by the Cryptex1 generic environment. This allows the PDI to adopt Cryptex1
     * personalization without requiring a new bespoke trust cache type.
     *
     * The personalization uses a Cryptex1 nonce domain, which is embedded within the
     * manifest itself.
     */
    kTCTypeCryptex1Generic = 0x16,

    /*
     * Type: Personalized (Cryptex1 Generic Supplemental)
     * Similar to the kTCTypeCryptex1Generic type except the manifest is signed by the
     * supplemental root of trust. Only viable for some data center use-cases.
     *
     * The personalization uses a Cryptex1 nonce domain, which is embedded within the
     * manifest itself.
     */
    kTCTypeCryptex1GenericSupplemental = 0x17,

    /*
     * Type: Personalized (Cryptex1 mobile asset brain)
     * This is exactly the same as the kTCTypeMobileAssetBrain type, except this using
     * the PDI nonce. The PDI nonce rolls every boot, and having a trust cache type
     * here helps create an asset brain personalization which works on the current
     * boot, but becomes invalid after a reboot, thus ensuring the brain which was
     * personalized will only remain valid for the current OS (this type is used by
     * the update brain which performs an OTA).
     */
    kTCTypeMobileAssetBrainEphemeral = 0x18,

    kTCTypeTotal,

    /* Invalid type */
    kTCTypeInvalid = 0xFF,
};

/* Availability macros for different trust cache types */
#define kLibTrustCacheHasCryptex1BootOS 1
#define kLibTrustCacheHasCryptex1BootApp 1
#define kLibTrustCacheHasCryptex1PreBootApp 1
#define kLibTrustCacheHasMobileAssetBrain 1
#define kLibTrustCacheHasSafariDownlevel 1
#define kLibTrustCacheHasCryptex1PreBootOS 1
#define kLibTrustCacheHasSupplementalPersistent 1
#define kLibTrustCacheHasSupplementalEphemeral 1
#define kLibTrustCacheHasCryptex1Generic 1
#define kLibTrustCacheHasCryptex1GenericSupplemental 1
#define kLibTrustCacheHasMobileAssetBrainEphemeral 1

typedef struct _TrustCache {
    /* Linked list linkage for the trust cache */
    struct _TrustCache *next;
    struct _TrustCache *prev;

    /* The type of this trust cache */
    TCType_t type;

    /* TODO: Add reference counts when we support unloading */

    /* The trust cache module itself */
    size_t moduleSize;
    const TrustCacheModuleBase_t *module;
} TrustCache_t;

typedef uint8_t TCQueryType_t;
enum {
    /* Query all types of trust caches in the runtime */
    kTCQueryTypeAll = 0x00,

    /* Static query type includes engineering trust caches */
    kTCQueryTypeStatic = 0x01,

    /* Most first party trust cache types are loadable ones */
    kTCQueryTypeLoadable = 0x02,

    kTCQueryTypeTotal,
};

typedef uint64_t TCCapabilities_t;
enum {
    /* Supports no capabilities */
    kTCCapabilityNone = 0,

    /* Supports the hash type field */
    kTCCapabilityHashType = (1 << 0),

    /* Supports the flags field */
    kTCCapabilityFlags = (1 << 1),

    /* Supports the constraints category field */
    kTCCapabilityConstraintsCategory = (1 << 2),
};

typedef struct _TrustCacheQueryToken {
    /* Trust cache where query was found */
    const TrustCache_t *trustCache;

    /* Entry within the trust cache where query was found */
    const void *trustCacheEntry;
} TrustCacheQueryToken_t;

/*
 * The runtime data structure is setup in a very special way. To make use of HW mitigations
 * offered by the silicon, the runtime can be placed in a region which is locked down by the
 * HW at some commit point. This theoretically allows the static and the engineering trust
 * caches to be locked down and immutable if the storage for the trust cache data structure
 * is also allocated within this same immutable memory segment.
 *
 * At the same time, we need to be able to support dynamically loaded trust caches on the
 * system. We can't keep a list head within the runtime for these trust caches, since that
 * head will be locked down when the runtime is locked, preventing us from adding a new link
 * in the chain. To solve this, the runtime instead stores a pointer to a wrapped data structure.
 * This pointer itself is locked down and can't be changed, but the contents of the wrapped
 * structure are mutable, making it a good place to store the linked list head.
 */

/* Data structure expected to be stored within mutable memory */
typedef struct _TrustCacheMutableRuntime {
    /* Loadable trust caches on the system */
    TrustCache_t *loadableTCHead;
} TrustCacheMutableRuntime_t;

/* Data structure expected to be stored within immutable memory */
typedef struct _TrustCacheRuntime {
    /* Runtime to use for image 4 object verification */
    const img4_runtime_t *image4RT;

    /* Configuration for trust cache types */
    bool allowSecondStaticTC;
    bool allowEngineeringTC;
    bool allowLegacyTC;

    /* Static trust cache for the system */
    TrustCache_t *staticTCHead;

    /* Engineering trust caches for the system */
    TrustCache_t *engineeringTCHead;

    /* Mutable runtime instance */
    TrustCacheMutableRuntime_t *mutableRT;
} TrustCacheRuntime_t;

__END_DECLS
#endif /* libTrustCache_Types_h */
STAGEEOF
    echo "Staged TrustCache/Types.h (no KDK)"
fi
if [ ! -f "EXTERNAL_HEADERS/TrustCache/TypesConfig.h" ]; then
    mkdir -p "EXTERNAL_HEADERS/TrustCache"
    cat > "EXTERNAL_HEADERS/TrustCache/TypesConfig.h" <<'STAGEEOF'
#ifndef libTrustCache_TypesConfig_h
#define libTrustCache_TypesConfig_h

#include <sys/cdefs.h>
__BEGIN_DECLS

#include <TrustCache/Types.h>

#if XNU_KERNEL_PRIVATE
/*
 * The AppleImage4 API definitions are accessed through the 'img4if' indirection
 * layer within XNU itself. Kernel extensions can access them directly from the
 * AppleImage4 headers.
 */
#include <libkern/img4/interface.h>
#endif

#if !XNU_KERNEL_PRIVATE
/*
 * XNU does not make this header available and uses different availability macros
 * than kernel extensions or base user-space applications.
 */
#include <TargetConditionals.h>
#endif

#pragma mark Chip Environments

static const img4_chip_t*
chipEnvironmentPersonalized(void) {
    return img4_chip_select_personalized_ap();
}

static const img4_chip_t*
chipEnvironmentCategorized(void) {
    return img4_chip_select_categorized_ap();
}

static const img4_chip_t*
chipEnvironmentGlobalFF00(void) {
    return IMG4_CHIP_AP_SOFTWARE_FF00;
}

static const img4_chip_t*
chipEnvironmentGlobalFF01(void) {
    return IMG4_CHIP_AP_SOFTWARE_FF01;
}

static const img4_chip_t*
chipEnvironmentGlobalFF06(void) {
    return IMG4_CHIP_AP_SOFTWARE_FF06;
}

static const img4_chip_t*
chipEnvironmentEphemeralCryptex(void) {
    return IMG4_CHIP_AP_SUPPLEMENTAL;
}

static const img4_chip_t*
chipEnvironmentCryptex1Boot(void) {
#if IMG4_API_VERSION >= 20211126
    return img4_chip_select_cryptex1_boot();
#else
    return NULL;
#endif
}

static const img4_chip_t*
chipEnvironmentCryptex1PreBoot(void) {
#if IMG4_API_VERSION >= 20211126
    return img4_chip_select_cryptex1_preboot();
#else
    return NULL;
#endif
}

static const img4_chip_t*
chipEnvironmentCryptex1MobileAsset(void) {
#if IMG4_API_VERSION >= 20211126
    return IMG4_CHIP_CRYPTEX1_ASSET;
#else
    return NULL;
#endif
}

static const img4_chip_t*
chipEnvironmentSafariDownlevel(void) {
#if IMG4_API_VERSION >= 20211126
    return IMG4_CHIP_CRYPTEX1_BOOT_REDUCED;
#else
    return NULL;
#endif
}

static const img4_chip_t*
chipEnvironmentSupplemental(void) {
    return IMG4_CHIP_AP_SUPPLEMENTAL;
}

static const img4_chip_t*
chipEnvironmentCryptex1Generic(void) {
#if IMG4_API_VERSION >= 20221202
    return IMG4_CHIP_CRYPTEX1_GENERIC;
#else
    return NULL;
#endif
}

static const img4_chip_t*
chipEnvironmentCryptex1GenericSupplemental(void) {
#if IMG4_API_VERSION >= 20221202
    return IMG4_CHIP_CRYPTEX1_GENERIC_SUPPLEMENTAL;
#else
    return NULL;
#endif
}

#pragma mark Nonce Domains

static const img4_nonce_domain_t*
nonceDomainTrustCache(void) {
    return IMG4_NONCE_DOMAIN_TRUST_CACHE;
}

static const img4_nonce_domain_t*
nonceDomainDDI(void) {
    return IMG4_NONCE_DOMAIN_DDI;
}

static const img4_nonce_domain_t*
nonceDomainCryptex(void) {
    return IMG4_NONCE_DOMAIN_CRYPTEX;
}

static const img4_nonce_domain_t*
nonceDomainEphemeralCryptex(void) {
    return IMG4_NONCE_DOMAIN_EPHEMERAL_CRYPTEX;
}

static const img4_nonce_domain_t*
nonceDomainPDI(void) {
    return IMG4_NONCE_DOMAIN_PDI;
}

#pragma mark Firmware Flags

static img4_firmware_flags_t
firmwareFlagsDTRS(void) {
    return IMG4_FIRMWARE_FLAG_RESPECT_AMNM;
}

static img4_firmware_flags_t
firmwareFlagsSplat(void) {
#if XNU_TARGET_OS_OSX && (defined(__arm__) || defined(__arm64__))
    return IMG4_FIRMWARE_FLAG_SUBSEQUENT_STAGE;
#elif defined(TARGET_OS_OSX) && TARGET_OS_OSX && (TARGET_CPU_ARM || TARGET_CPU_ARM64)
    return IMG4_FIRMWARE_FLAG_SUBSEQUENT_STAGE;
#else
    return IMG4_FIRMWARE_FLAG_INIT;
#endif
}

#pragma mark Type Configuration

typedef struct _TrustCacheTypeConfig {
    /* Chip environment to use for validation */
    const img4_chip_t* (*chipEnvironment)(void);

    /* Nonce domain for anti-replay */
    const img4_nonce_domain_t* (*nonceDomain)(void);

    /* Four CC identifier for this type */
    img4_4cc_t fourCC;

    /* Firmware flags to add for this configuration */
    img4_firmware_flags_t (*firmwareFlags)(void);

    /*
     * Higher level policy imposes restrictions on which process can load
     * which trust cache. These restrictions are enforced through the use
     * of the entitlement "com.apple.private.pmap.load-trust-cache". The
     * value here is the required value of the above entitlement.
     */
    const char *entitlementValue;
} TrustCacheTypeConfig_t;

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wfour-char-constants"

static const TrustCacheTypeConfig_t TCTypeConfig[kTCTypeTotal] = {
    /* Static trust caches are loaded as raw modules */
    [kTCTypeStatic] = {
        .chipEnvironment = NULL,
        .nonceDomain = NULL,
        .fourCC = 0,
        .firmwareFlags = NULL,
        .entitlementValue = NULL
    },

    /* Engineering trust caches are loaded as raw modules */
    [kTCTypeEngineering] = {
        .chipEnvironment = NULL,
        .nonceDomain = NULL,
        .fourCC = 0,
        .firmwareFlags = NULL,
        .entitlementValue = NULL
    },

    /* Legacy trust caches are loaded as raw modules */
    [kTCTypeLegacy] = {
        .chipEnvironment = NULL,
        .nonceDomain = NULL,
        .fourCC = 0,
        .firmwareFlags = NULL,
        .entitlementValue = NULL
    },

    [kTCTypeDTRS] = {
        .chipEnvironment = chipEnvironmentPersonalized,
        .nonceDomain = NULL,
        .fourCC = 'dtrs',
        .firmwareFlags = firmwareFlagsDTRS,
        .entitlementValue = "personalized.engineering-root"
    },

    [kTCTypeLTRS] = {
        .chipEnvironment = chipEnvironmentPersonalized,
        .nonceDomain = nonceDomainTrustCache,
        .fourCC = 'ltrs',
        .firmwareFlags = NULL,
        .entitlementValue = "personalized.trust-cache"
    },

    [kTCTypePersonalizedDiskImage] = {
        .chipEnvironment = chipEnvironmentPersonalized,
        .nonceDomain = nonceDomainPDI,
        .fourCC = 'ltrs',
        .firmwareFlags = NULL,
        .entitlementValue = "personalized.pdi"
    },

    [kTCTypeDeveloperDiskImage] = {
        .chipEnvironment = chipEnvironmentCategorized,
        .nonceDomain = nonceDomainDDI,
        .fourCC = 'trdv',
        .firmwareFlags = NULL,
        .entitlementValue = "personalized.ddi"
    },

    [kTCTypeLTRSWithDDINonce] = {
        .chipEnvironment = chipEnvironmentPersonalized,
        .nonceDomain = nonceDomainDDI,
        .fourCC = 'ltrs',
        .firmwareFlags = NULL,
        .entitlementValue = "personalized.ddi"
    },

    [kTCTypeCryptex] = {
        .chipEnvironment = chipEnvironmentPersonalized,
        .nonceDomain = nonceDomainCryptex,
        .fourCC = 'ltrs',
        .firmwareFlags = NULL,
        .entitlementValue = "personalized.cryptex-research"
    },

    [kTCTypeEphemeralCryptex] = {
        .chipEnvironment = chipEnvironmentEphemeralCryptex,
        .nonceDomain = nonceDomainEphemeralCryptex,
        .fourCC = 'ltrs',
        .firmwareFlags = NULL,
        .entitlementValue = "personalized.ephemeral-cryptex"
    },

    [kTCTypeUpdateBrain] = {
        .chipEnvironment = chipEnvironmentGlobalFF00,
        .nonceDomain = NULL,
        .fourCC = 'ltrs',
        .firmwareFlags = NULL,
        .entitlementValue = "global.ota-update-brain"
    },

    [kTCTypeInstallAssistant] = {
        .chipEnvironment = chipEnvironmentGlobalFF01,
        .nonceDomain = NULL,
        .fourCC = 'ltrs',
        .firmwareFlags = NULL,
        .entitlementValue = "global.install-assistant"
    },

    [kTCTypeBootabilityBrain] = {
        .chipEnvironment = chipEnvironmentGlobalFF06,
        .nonceDomain = NULL,
        .fourCC = 'trbb',
        .firmwareFlags = NULL,
        .entitlementValue = "global.bootability-brain"
    },

    [kTCTypeCryptex1BootOS] = {
        .chipEnvironment = chipEnvironmentCryptex1Boot,
        .nonceDomain = NULL,
        .fourCC = 'trcs',
        .firmwareFlags = firmwareFlagsSplat,
        .entitlementValue = "cryptex1.boot.os"
    },

    [kTCTypeCryptex1BootApp] = {
        .chipEnvironment = chipEnvironmentCryptex1Boot,
        .nonceDomain = NULL,
        .fourCC = 'trca',
        .firmwareFlags = firmwareFlagsSplat,
        .entitlementValue = "cryptex1.boot.app"
    },

    [kTCTypeCryptex1PreBootApp] = {
        .chipEnvironment = chipEnvironmentCryptex1PreBoot,
        .nonceDomain = NULL,
        .fourCC = 'trca',
        .firmwareFlags = firmwareFlagsSplat,
        .entitlementValue = "cryptex1.preboot.app"
    },

    [kTCTypeGlobalDiskImage] = {
        .chipEnvironment = chipEnvironmentGlobalFF00,
        .nonceDomain = NULL,
        .fourCC = 'ltrs',
        .firmwareFlags = NULL,
        .entitlementValue = "global.pdi"
    },

    [kTCTypeMobileAssetBrain] = {
        .chipEnvironment = chipEnvironmentCryptex1MobileAsset,
        .nonceDomain = NULL,
        .fourCC = 'trab',
        .firmwareFlags = NULL,
        .entitlementValue = "personalized.mobile-asset-brain"
    },

    [kTCTypeSafariDownlevel] = {
        .chipEnvironment = chipEnvironmentSafariDownlevel,
        .nonceDomain = NULL,
        .fourCC = 'trca',
        .firmwareFlags = NULL,
        .entitlementValue = "cryptex1.safari-downlevel"
    },

    [kTCTypeCryptex1PreBootOS] = {
        .chipEnvironment = chipEnvironmentCryptex1PreBoot,
        .nonceDomain = NULL,
        .fourCC = 'trcs',
        .firmwareFlags = firmwareFlagsSplat,
        .entitlementValue = "cryptex1.preboot.os"
    },

    [kTCTypeSupplementalPersistent] = {
        .chipEnvironment = chipEnvironmentSupplemental,
        .nonceDomain = nonceDomainDDI,
        .fourCC = 'ltrs',
        .firmwareFlags = NULL,
        .entitlementValue = "personalized.supplemental-persistent"
    },

    [kTCTypeSupplementalEphemeral] = {
        .chipEnvironment = chipEnvironmentSupplemental,
        .nonceDomain = nonceDomainPDI,
        .fourCC = 'ltrs',
        .firmwareFlags = NULL,
        .entitlementValue = "personalized.supplemental-ephemeral"
    },

    [kTCTypeCryptex1Generic] = {
        .chipEnvironment = chipEnvironmentCryptex1Generic,
        .nonceDomain = NULL,
        .fourCC = 'gtcd',
        .firmwareFlags = NULL,
        .entitlementValue = "cryptex1.generic"
    },

    [kTCTypeCryptex1GenericSupplemental] = {
        .chipEnvironment = chipEnvironmentCryptex1GenericSupplemental,
        .nonceDomain = NULL,
        .fourCC = 'gtcd',
        .firmwareFlags = NULL,
        .entitlementValue = "cryptex1.generic.supplemental"
    },

    [kTCTypeMobileAssetBrainEphemeral] = {
        .chipEnvironment = chipEnvironmentCryptex1MobileAsset,
        .nonceDomain = nonceDomainPDI,
        .fourCC = 'trab',
        .firmwareFlags = NULL,
        .entitlementValue = "personalized.mobile-asset-brain"
    },
};

#pragma GCC diagnostic pop

__END_DECLS
#endif /* libTrustCache_TypesConfig_h */
STAGEEOF
    echo "Staged TrustCache/TypesConfig.h (no KDK)"
fi
if [ ! -f "EXTERNAL_HEADERS/CoreEntitlements/CoreEntitlements.h" ]; then
    mkdir -p "EXTERNAL_HEADERS/CoreEntitlements"
    cat > "EXTERNAL_HEADERS/CoreEntitlements/CoreEntitlements.h" <<'STAGEEOF'
/*!
 * @header
 * Umbrella header for CoreEntitlements
 */
#ifndef CORE_ENTITLEMENTS_H
#define CORE_ENTITLEMENTS_H

/*
 * Web-browser-engine hardened-runtime entitlement keys. Upstream xnu defines
 * these in the KDK-only CodeSignature/Entitlements.h; dxb instead places them
 * in CoreEntitlements.h (see dxb patches/14.x-15.x entitlements.patch). We
 * stage the same definitions here so kern_exec.c / necp_client.c resolve.
 */
#define kCSWebBrowserNetworkEntitlement     (("com.apple.developer.web-browser-engine.networking"))
#define kCSWebBrowserWebContentEntitlement  (("com.apple.developer.web-browser-engine.webcontent"))
#define kCSWebBrowserGPUEntitlement         (("com.apple.developer.web-browser-engine.rendering"))
#define kCSWebBrowserHostEntitlement        (("com.apple.developer.web-browser-engine.host"))

#ifdef __cplusplus
extern "C" {
#endif

typedef const struct CERuntime* CERuntime_t;
typedef struct CEQueryContext* CEQueryContext_t;

#define _CE_INDIRECT 1

#ifdef TXM
#include <attributes.h>
#include <ptrcheck.h>
#endif

#if defined(__has_feature) && __has_feature(bounds_attributes)
#define CE_HEADER_INDEXABLE __attribute__((__indexable__))
#else
#define CE_HEADER_INDEXABLE
#endif

#include <os/base.h>
#include <CoreEntitlements/Errors.h>
#include <CoreEntitlements/Result.h>
#include <CoreEntitlements/Runtime.h>
#include <CoreEntitlements/Entitlements.h>
#include <CoreEntitlements/Serialization.h>
#include <CoreEntitlements/Index.h>

__ptrcheck_abi_assume_single();

/*!
 * @typedef CEType_t
 * @brief Represents a type of element supported by CoreEntitlements
 *
 * @const kCETypeUnknown
 * An unknown type
 *
 * @const kCETypeDictionary
 * A dictionary container
 *
 * @const kCETypeSequence
 * An ordered sequence container
 *
 * @const kCETypeInteger
 * An integer.
 *
 * @const kCETypeString
 * A string of bytes.
 *
 * @const kCETypeBool
 * A boolean.
 */
OS_CLOSED_ENUM(CEType, uint32_t,
               kCETypeUnknown = 0,
               kCETypeDictionary = 1,
               kCETypeSequence = 2,
               kCETypeInteger = 3,
               kCETypeString = 4,
               kCETypeBool = 5,
               kCETypeData = 6);

/*!
 * @function CE_RT_LOG
 * Log a single message via the current runtime
 * Only called if the runtime supports logging.
 */
#define CE_RT_LOG(msg) do { if (rt->log) { rt->log(rt, "[%s]: %s\n", __FUNCTION__, msg); } } while(0)

/*!
 * @function CE_RT_LOGF
 * Logs using the passed in format. Printf like.
 * Only called if the runtime supports logging.
 */
#define CE_RT_LOGF(fmt, ...) do { if (rt->log) { rt->log(rt, "[%s]: " fmt, __FUNCTION__, __VA_ARGS__); } } while(0)

/*!
 * @function CE_RT_ABORT
 * Invokes the runtime abort function with a passed in message.
 * This function should not return.
 */
#define CE_RT_ABORT(...) do { rt->abort(rt, "[%s]: %s\n", __FUNCTION__, __VA_ARGS__); } while(0)

#ifdef __cplusplus
}
#endif

#endif
STAGEEOF
    echo "Staged CoreEntitlements/CoreEntitlements.h (no KDK)"
fi
if [ ! -f "EXTERNAL_HEADERS/CoreEntitlements/CoreEntitlementsPriv.h" ]; then
    mkdir -p "EXTERNAL_HEADERS/CoreEntitlements"
    cat > "EXTERNAL_HEADERS/CoreEntitlements/CoreEntitlementsPriv.h" <<'STAGEEOF'
//
//  CoreEntitlementsPriv.h
//  CoreEntitlements
//

#ifndef CORE_ENTITLEMENTS_PRIV_H
#define CORE_ENTITLEMENTS_PRIV_H

#ifdef __cplusplus
extern "C" {
#endif

#include <CoreEntitlements/CoreEntitlements.h>
#include <CoreEntitlements/EntitlementsPriv.h>

#define CE_BRIDGE_STRUCT_VERSION 3
#define CCDER_ENTITLEMENTS (CCDER_SEQUENCE | CCDER_CONSTRUCTED | CCDER_APPLICATION)

__ptrcheck_abi_assume_single();

/*!
 * @typedef coreentitlements_t
 * Wraps up all the CoreEntitlements functions into a nice bundle to be used in the kernel
 */
typedef struct {
    uint64_t version;
    typeof(&CEAcquireUnmanagedContext) AcquireUnmanagedContext;
    typeof(&CEValidate) Validate;
    typeof(&CEContextQuery) ContextQuery;
    typeof(&CEConjureContextFromDER) ConjureContextFromDER;
    
    typeof(&der_vm_context_create) der_vm_context_create;
    typeof(&der_vm_execute) der_vm_execute;
    typeof(&der_vm_iterate) der_vm_iterate;
    typeof(&der_vm_context_is_valid) der_vm_context_is_valid;
    typeof(&der_vm_CEType_from_context) der_vm_CEType_from_context;
    typeof(&der_vm_integer_from_context) der_vm_integer_from_context;
    typeof(&der_vm_string_from_context) der_vm_string_from_context;
    typeof(&der_vm_bool_from_context) der_vm_bool_from_context;
    
    typeof(kCENoError) kNoError;
    typeof(kCEAPIMisuse) kAPIMisuse;
    typeof(kCEInvalidArgument) kInvalidArgument;
    typeof(kCEAllocationFailed) kAllocationFailed;
    typeof(kCEMalformedEntitlements) kMalformedEntitlements;
    typeof(kCEQueryCannotBeSatisfied) kQueryCannotBeSatisfied;
#if CE_ACCELERATION_SUPPORTED
    typeof(kCENotEligibleForAcceleration) kNotEligibleForAcceleration;
#endif

    typeof(&CEGetErrorString) GetErrorString;
    
    typeof(&der_vm_buffer_from_context) der_vm_buffer_from_context;
    typeof(&CEContextIsSubset) CEContextIsSubset;
    
#if CE_ACCELERATION_SUPPORTED
    typeof(&CEIndexSizeForContext) IndexSizeForContext;
    typeof(&CEBuildIndexForContext) BuildIndexForContext;
    typeof(&CEFreeIndexForContext) FreeIndexForContext;
    typeof(&CEContextIsAccelerated) ContextIsAccelerated;
#endif
} coreentitlements_t;

#ifdef __BLOCKS__
typedef bool (^iteration_trampoline_t)(der_vm_iteration_context ctx);
bool der_vm_block_trampoline(der_vm_iteration_context ctx);
#endif

/*
 These are private for now, they're essentially inverse functions for CESerialize.
 
 */
CEError_t CESizeDeserialization(CEQueryContext_t ctx, size_t* requiredElements);
CEError_t CEDeserialize(CEQueryContext_t ctx, CESerializedElement_t *__counted_by(elementsLength) elements, size_t elementsLength);

#ifdef __cplusplus
}
#endif

#endif
STAGEEOF
    echo "Staged CoreEntitlements/CoreEntitlementsPriv.h (no KDK)"
fi
if [ ! -f "EXTERNAL_HEADERS/CoreEntitlements/Entitlements.h" ]; then
    mkdir -p "EXTERNAL_HEADERS/CoreEntitlements"
    cat > "EXTERNAL_HEADERS/CoreEntitlements/Entitlements.h" <<'STAGEEOF'
//
//  Entitlements.h
//  CoreEntitlements
//
//

#ifndef CORE_ENTITLEMENTS_ENTITLEMENTS_H
#define CORE_ENTITLEMENTS_ENTITLEMENTS_H

#ifndef _CE_INDIRECT
#error "Please include <CoreEntitlements/CoreEntitlements.h> instead of this file"
#endif

#include <CoreEntitlements/Result.h>
#include <CoreEntitlements/Runtime.h>

__ptrcheck_abi_assume_single();

/*!
 * @enum CEVersion_t
 * Represents the various versions supported by CoreEntitlements
 */
OS_ENUM(CEVersion, int64_t,
        kCEVersionInvalid = 0,
        kCEVersionZero = 1,
        kCEVersionOne = 2);

/*!
 * @struct CEValidationResult
 * Contains the result of the call to CEValidate
 */
typedef struct {
    CEVersion_t version;
    const uint8_t *__ended_by(blob_end) blob;
    const uint8_t * blob_end;
} CEValidationResult;

typedef struct {
    bool allow_data_elements;
} CEValidationOptions;

/*!
 * @function CEValidate
 * Validates if the provided blob conforms to one of the entitlement specification understood by CoreEntitlements
 * @param rt
 * Active runtime
 * @param result
 * The validation result will be stored here
 * @param blob
 * Pointer to the start of the entitlements object
 * @param blob_end
 * Pointer to one byte past the end of the entitlements object
 * @discussion
 * This function will return kCENoError if the entitlements are valid
 */
CEError_t CEValidate(const CERuntime_t rt, CEValidationResult* result, const uint8_t *__ended_by(blob_end) blob, const uint8_t* blob_end) __result_use_check;
/*!
 * @function CEValidateWithOptions
 * Validates if the provided blob conforms to one of the entitlement specification understood by CoreEntitlements
 * @param rt
 * Active runtime
 * @param options
 * Options that modify how validation behaves
 * @param result
 * The validation result will be stored here
 * @param blob
 * Pointer to the start of the entitlements object
 * @param blob_end
 * Pointer to one byte past the end of the entitlements object
 * @discussion
 * This function will return kCENoError if the entitlements are valid
 */
CEError_t CEValidateWithOptions(const CERuntime_t rt, CEValidationOptions* options, CEValidationResult* result, const uint8_t *__ended_by(blob_end) blob, const uint8_t* blob_end) __result_use_check;

/*!
 * @function CEAcquireManagedContext
 * Creates and returns a managed query context for the validated blob against which you can perform queries
 * @param rt
 * Active runtime (must support allocation and deallocation)
 * @param validationResult
 * The validation result returned by  CEValidate
 * @param ctx
 * Pointer to where the context is to be returned
 * @note
 * The returned managed context must be subsequently released with CEAcquireManagedContext
 */
CEError_t CEAcquireManagedContext(const CERuntime_t rt, CEValidationResult validationResult, CEQueryContext_t* ctx) __result_use_check;

/*!
 @discussion
 Releases the managed context
 */
CEError_t CEReleaseManagedContext(CEQueryContext_t* ctx);

/*!
 * @enum CEQueryOpOpcode_t
 * These are all the supported operations by the CoreEntitlements VM
 */
OS_ENUM(CEQueryOpOpcode, int64_t,
        kCEOpNoop = 0,
        kCEOpSelectKey = 1,
        kCEOpSelectIndex = 2,
        kCEOpMatchString = 3,
        kCEOpMatchStringPrefix = 4,
        kCEOpMatchBool = 5,
        kCEOpStringValueAllowed = 6,
        kCEOpMatchInteger = 7,
        kCEOpStringPrefixValueAllowed = 8,
        kCEOpSelectKeyWithPrefix = 9,
        kCEOpIntegerValueAllowed = 10,
        kCEOpMatchType = 11,
        kCEOpMatchData = 12,
        kCEOpMatchDataValueAllowed = 13,
        kCEOpMaxOperation = 14, /* Sentinel value */
        kCEOpDynamic = 0x1LL << 62);



/*!
 * @typedef CEQueryOperation_t
 * Represents an operation within the DERQL interpreter
 * The opcode specified _which_ operation to perform, while the parameters specify how to perform it.
 * Operations are passed by value and may be safely reused.
 */
typedef struct CEQueryOperation {
    CEQueryOpOpcode_t opcode;
    union {
        CEBuffer dynamicParameter;
        CEStaticBuffer stringParameter;
        int64_t numericParameter;
    } parameters;
} CEQueryOperation_t;

typedef CEQueryOperation_t CEQuery_t[];

extern const CEQueryOperation_t* CESelectKeyOperation;
extern const CEQueryOperation_t* CESelectValueOperation;

/*!
 * @typedef CEPrepareOptions_t
 * Containts the options you may pass in to CEPrepareQuery.
 */
typedef struct CEPrepareOptions {
    /*
     If materialize is true dynamic ops are turned into static ones
     */
    bool materialize;
    /*
     Controls if CEPrepareQuery should fail on keys in dynamic operations that are too long
     */
    bool failOnOversizedParameters;
} CEPrepareOptions_t;

/*!
 * @function CEContextQuery
 * Performs a query on the passed in CEQueryContext_t
 *
 * @param ctx
 * The context on which to perform the query
 *
 * @param query
 * The sequence of operations to execute
 *
 * @param queryLength
 * The number of operations in the query
 *
 * @returns
 * This function will return kCENoError if the query is satisfiable, otherwise kCEQueryCannotBeSatisfied.
 *
 * @note
 * As stated previously, the query only succeeds if it is satisfiable by the context, meaning that the operations executed in the passed in order
 * leave the VM in the valid state. An invalid state may arise from a variety of situations, like trying to select a value for a key that doesn't exist,
 * or a failing string matching operations.
 */
CEError_t CEContextQuery(CEQueryContext_t ctx, const CEQueryOperation_t *__counted_by(queryLength) query, size_t queryLength) __result_use_check;

/*!
 * @function CEPrepareQuery
 * Prepares the query for execution by materializing dynamic operations if needed
 * 
 * @params options
 * Options to control how the query should be prepared
 *
 * @param query
 * The sequence of operations to prepare
 *
 * @param queryLength
 * The number of operations in the query
 */
CEError_t CEPrepareQuery(CEPrepareOptions_t options, CEQueryOperation_t *__counted_by(queryLength) query, size_t queryLength);

/*!
 * @function CEContextIsSubset
 * Checks if the subset <-> superset relation holds between two context.
 * The logic relations used to establish that relation correspond to the normal profile-validation rules.
 *
 * @param subset
 * The context that is meant to a subset
 *
 * @param superset
 * The context that is meant to be a superset
 *
 * @returns
 * This function will return kCENoError if the relation holds, otherwise kCEQueryCannotBeSatisfied.
 */
CEError_t CEContextIsSubset(CEQueryContext_t subset, CEQueryContext_t superset);

#include <CoreEntitlements/QueryHelpers.h>

#endif
STAGEEOF
    echo "Staged CoreEntitlements/Entitlements.h (no KDK)"
fi
if [ ! -f "EXTERNAL_HEADERS/CoreEntitlements/EntitlementsPriv.h" ]; then
    mkdir -p "EXTERNAL_HEADERS/CoreEntitlements"
    cat > "EXTERNAL_HEADERS/CoreEntitlements/EntitlementsPriv.h" <<'STAGEEOF'
//
//  EntitlementsPriv.h
//  CoreEntitlements
//


#ifndef CORE_ENTITLEMENTS_ENTS_PRIV_H
#define CORE_ENTITLEMENTS_ENTS_PRIV_H

#ifdef __cplusplus
extern "C" {
#endif

#include <CoreEntitlements/Entitlements.h>
#include <CoreEntitlements/der_vm.h>

#ifndef CORE_ENTITLEMENTS_I_KNOW_WHAT_IM_DOING
#error This is a private API, please consult with the Trusted Execution team before using this. Misusing these functions will lead to security issues.
#endif

__ptrcheck_abi_assume_single();

struct CEQueryContext {
    der_vm_context_t der_context;
    bool managed;
};


CEError_t CEAcquireUnmanagedContext(const CERuntime_t rt, CEValidationResult validationResult, struct CEQueryContext* ctx);

/*!
 * @function CEConjureContextFromDER
 * @brief Conjures up an object from thin air that you can query. Don't use it.
 * @note It does no validation.
 */
struct CEQueryContext CEConjureContextFromDER(der_vm_context_t der_context);

CEQueryOperation_t* CECreateStringOpInplace(CEQueryOperation_t* storage, CEQueryOpOpcode_t op, const char *__counted_by(len) data, size_t len);
CEQueryOperation_t* CECreateNumericOpInplace(CEQueryOperation_t* storage, CEQueryOpOpcode_t op, int64_t param);

#ifdef __cplusplus
}
#endif

#endif
STAGEEOF
    echo "Staged CoreEntitlements/EntitlementsPriv.h (no KDK)"
fi
if [ ! -f "EXTERNAL_HEADERS/CoreEntitlements/Errors.h" ]; then
    mkdir -p "EXTERNAL_HEADERS/CoreEntitlements"
    cat > "EXTERNAL_HEADERS/CoreEntitlements/Errors.h" <<'STAGEEOF'
//
//  Errors.h
//  CoreEntitlements
//
//

#ifndef CORE_ENTITLEMENTS_ERRORS_H
#define CORE_ENTITLEMENTS_ERRORS_H

#ifndef _CE_INDIRECT
#error "Please include <CoreEntitlements/CoreEntitlements.h> instead of this file"
#endif

#include <sys/cdefs.h>
__ptrcheck_abi_assume_single();

/*!
 * @typedef CEError_t
 * A shared error type that is returned by CoreEntitlements APIs
 */
typedef const struct CEError *__single CEError_t;

// Macro to define the error for export;
#define CE_DEF_ERROR(name) extern CEError_t name;

// Returned on successful invocation
CE_DEF_ERROR(kCENoError);

// Returned when the library encounters API misuse
CE_DEF_ERROR(kCEAPIMisuse);

// Returned when an invalid argument has been passed in
CE_DEF_ERROR(kCEInvalidArgument);

// Returned when we expected to have allocated data, but we couldn't
CE_DEF_ERROR(kCEAllocationFailed);

// Returned when the passed in entitlements do not conform to any supported format
CE_DEF_ERROR(kCEMalformedEntitlements);

// Returned when a group of queries does not generate a valid result on the current CEQueryContext
CE_DEF_ERROR(kCEQueryCannotBeSatisfied);

// Returned when a context shouldn't be accelerated
CE_DEF_ERROR(kCENotEligibleForAcceleration);

/*!
 * @function CEGetErrorString
 * Returns a string that describes the error
 */
const char *__unsafe_indexable CEGetErrorString(CEError_t error);

#endif
STAGEEOF
    echo "Staged CoreEntitlements/Errors.h (no KDK)"
fi
if [ ! -f "EXTERNAL_HEADERS/CoreEntitlements/Index.h" ]; then
    mkdir -p "EXTERNAL_HEADERS/CoreEntitlements"
    cat > "EXTERNAL_HEADERS/CoreEntitlements/Index.h" <<'STAGEEOF'
//
//  Index.h
//  CoreEntitlements
//
//

#ifndef CORE_ENTITLEMENTS_INDEX_H
#define CORE_ENTITLEMENTS_INDEX_H

#ifndef _CE_INDIRECT
#error "Please include <CoreEntitlements/CoreEntitlements.h> instead of this file"
#endif

#include <CoreEntitlements/Result.h>

/*
 The kernel always supports acceleration
 */
#define CE_ACCELERATION_SUPPORTED 1


/*!
 @typedef CEAccelerationElement_t
 
 A single element of the acceleration structure, the contents of this struct are an implementation detail
 and are subject to change.
 */
typedef struct CEAccelerationElement {
    uint32_t key_offset;
    uint32_t key_length;
} CEAccelerationElement_t;

/*!
 @struct CEAccelerationContext
 
 Contains data required to accelerate queries, the contents of this struct are an implementation detail
 and are subject to change.
 */
struct CEAccelerationContext {
    CEAccelerationElement_t * __counted_by(index_count) index;
    size_t index_count;
};

/*!
 @function CEIndexSizeForContext
 Computes an upper bound of memory needed to construct an acceleration index for a particular query context.
 
 @param context
 The context for which the calculation should be made
 
 @param size
 Contains the required size, in bytes.
 
 @returns an error if the context cannot be accelerated, success otherwise
 */
CEError_t CEIndexSizeForContext(CEQueryContext_t context, size_t* size);

/*!
 @function CEBuildIndexForContext
 Computes and stores and acceleration index into the passed in context.
 Building an index requires runtime support.
 
 @param context
 The context for which the index should be computed.
 */
CEError_t CEBuildIndexForContext(CEQueryContext_t context);

/*!
 @function CEFreeIndexForContext
 Frees an index associated with a query context
 
 @param context
 The context for which the index should be freed.
 */
CEError_t CEFreeIndexForContext(CEQueryContext_t context);

/*!
 @function CEContextIsAccelerated
 Checks if the passed in context supports query acceleration
 
 @param context
 The context to check.
 */
bool CEContextIsAccelerated(CEQueryContext_t context);

#endif /* CORE_ENTITLEMENTS_INDEX_H */
STAGEEOF
    echo "Staged CoreEntitlements/Index.h (no KDK)"
fi
if [ ! -f "EXTERNAL_HEADERS/CoreEntitlements/KernelUtils.hpp" ]; then
    mkdir -p "EXTERNAL_HEADERS/CoreEntitlements"
    cat > "EXTERNAL_HEADERS/CoreEntitlements/KernelUtils.hpp" <<'STAGEEOF'
//
//  KernelUtils.hpp
//  CoreEntitlements_kernel
//
//

#ifndef CORE_ENTITLEMENTS_KERNEL_H
#define CORE_ENTITLEMENTS_KERNEL_H

#include <CoreEntitlements/CoreEntitlements.h>
#include <libkern/c++/OSPtr.h>
#include <libkern/c++/OSDictionary.h>

#ifndef CORE_ENTITLEMENTS_I_KNOW_WHAT_IM_DOING
#error This is a private API, please consult with the Trusted Execution team before using this. Misusing these functions will lead to security issues.
#endif

/*!
 * @function CEQueryContextToOSDictionary
 * Private API, converts a query context into an OSDictionary that can be handed out to legacy users
 */
OSPtr<OSDictionary> CEQueryContextToOSDictionary(CEQueryContext_t entitlements);

/*!
 * @function CEQueryContextToOSObject
 * Private API, converts a query context into an OSObject that may be returned dynamically
 */
OSPtr<OSObject> CEQueryContextToOSObject(CEQueryContext_t context);

#endif
STAGEEOF
    echo "Staged CoreEntitlements/KernelUtils.hpp (no KDK)"
fi
if [ ! -f "EXTERNAL_HEADERS/CoreEntitlements/QueryHelpers.h" ]; then
    mkdir -p "EXTERNAL_HEADERS/CoreEntitlements"
    cat > "EXTERNAL_HEADERS/CoreEntitlements/QueryHelpers.h" <<'STAGEEOF'
//
//  QueryHelpers.h
//  CoreEntitlements
//

#ifndef CORE_ENTITLEMENTS_HELPERS_H
#define CORE_ENTITLEMENTS_HELPERS_H

#include <sys/cdefs.h>
__ptrcheck_abi_assume_single();

/*!
 * @function CEDynamic
 * Marks an opcode as being dynamic
 *
 * @param op
 * Opcode
 */
#define CEDynamic(op) (CEQueryOpOpcode_t)((op) | kCEOpDynamic)

/*!
 * @function CESelectIndex
 * Returns an operation that when executed will modify the context such that any subsequent operation is performed on the entitlement object at the specified index
 *
 * @param index
 * The index of the object within a container
 *
 * @discussion
 * Using an index that is past the container's size will result in an invalid context
 */
#define CESelectIndex(index) (CEQueryOperation_t){.opcode = kCEOpSelectIndex, .parameters = {.numericParameter = index}}

/*!
 * @function CESelectKey
 * Returns an operation that when executed will modify the context such that any subsequent operation is performed on the key of the dictionary pair
 * @discussion
 * Selecting a key on a non-dictionary-pair object is undefined behavior (i..e. it is implementation defined)
 */
#define CESelectKey() CESelectIndex(0)

/*!
 * @function CESelectValue
 * Returns an operation that when executed will modify the context such that any subsequent operation is performed on the value of the dictionary pair
 * @discussion
 * Selecting a value on a non-dictionary-pair object is undefined behavior (i..e. it is implementation defined)
 */
#define CESelectValue() CESelectIndex(1)


/*!
 * @function CESelectDictValue
 * Returns an operation that when executed will modify the context such that any subsequent operation is performed on the object that corresponds
 * to the value pointed to by the specified key
 *
 * @param key
 * The key of the object within a container
 *
 * @discussion
 * Using a key that is not found in the container will result in an invalid context
 */
#define CESelectDictValue(key) (CEQueryOperation_t){.opcode = kCEOpSelectKey, .parameters = {.stringParameter = {.data = key, .length = sizeof(key) - 1}}}
#define CESelectDictValueDynamic(key, len) (CEQueryOperation_t){.opcode = CEDynamic(kCEOpSelectKey), .parameters = {.dynamicParameter = {.data = key, .length = len}}}

/*!
 * @function CEMatchString
 * Returns an operation that will return a valid context if and only if the context corresponds to a valid string and matches the string exactly
 *
 * @param string
 * The string to match against (MUST BE A STRING LITERAL)
 *
 * @discussion
 * If a valid context is returned it will be in the same state as the execution context
 */
#define CEMatchString(string) (CEQueryOperation_t){.opcode = kCEOpMatchString, .parameters = {.stringParameter = {.data = string, .length = sizeof(string) - 1}}}
#define CEMatchDynamicString(string, len) (CEQueryOperation_t){.opcode = CEDynamic(kCEOpMatchString), .parameters = {.dynamicParameter = {.data = string, .length = len}}}

/*!
 * @function CEMatchPrefix
 * Returns an operation that will return a valid context if and only if the context corresponds to a valid string and it's prefix matched the passed in prefix
 *
 * @param prefix
 * The prefix to match against (MUST BE A STRING LITERAL)
 *
 * @discussion
 * If a valid context is returned it will be in the same state as the execution context
 */
#define CEMatchPrefix(prefix) (CEQueryOperation_t){.opcode = kCEOpMatchStringPrefix, .parameters = {.stringParameter = {.data = prefix, .length = sizeof(prefix) - 1}}}
#define CEMatchDynamicPrefix(prefix, len) (CEQueryOperation_t){.opcode = CEDynamic(kCEOpMatchStringPrefix), .parameters = {.dynamicParameter = {.data = prefix, .length = len}}}

/*!
 * @function CEMatchType
 * Returns an operation that will return a valid context if and only if the type selected by the context corresponds to the one passed in.
 *
 * @param type
 * The type to match against
 *
 * @discussion
 * If a valid context is returned it will be in the same state as the execution context
 */
#define CEMatchType(type) (CEQueryOperation_t){.opcode = kCEOpMatchType, .parameters = {.numericParameter = (int64_t)type}}

/*!
 * @function CEMatchBool
 * Returns an operation that will return a valid context if and only if the context corresponds to a valid boolean and matches the boolean exactly
 *
 * @param val
 * The bool to match against
 *
 * @discussion
 * If a valid context is returned it will be in the same state as the execution context
 */
#define CEMatchBool(val) (CEQueryOperation_t){.opcode = kCEOpMatchBool, .parameters = {.numericParameter = !!val}}

/*!
 * @function CEMatchInteger
 * Returns an operation that will return a valid context if and only if the context corresponds to a valid integer and matches the integer exactly
 *
 * @param val
 * The integer to match against
 *
 * @discussion
 * If a valid context is returned it will be in the same state as the execution context
 */
#define CEMatchInteger(val) (CEQueryOperation_t){.opcode = kCEOpMatchInteger, .parameters = {.numericParameter = val}}

/*!
 * @function CEIsIntegerAllowed
 * Returns an operation that will return a valid context if 1) the current context is an integer and allows the integer, or 2) the context is an array of integers that allows the integer
 *
 * @param integer
 * The integer to match against
 *
 * @discussion
 * If a valid context is returned it will be in the same state as the execution context
 */
#define CEIsIntegerAllowed(integer) (CEQueryOperation_t){.opcode = kCEOpIntegerValueAllowed, .parameters = {.numericParameter = integer}}

/*!
 * @function CEIsStringAllowed
 * Returns an operation that will return a valid context if 1) the current context is a string and allows the string via wildcard rules, or 2) the context is an array of strings that allows the string
 *
 * @param string
 * The string to match against (MUST BE A STRING LITERAL)
 *
 * @discussion
 * If a valid context is returned it will be in the same state as the execution context
 */
#define CEIsStringAllowed(string) (CEQueryOperation_t){.opcode = kCEOpStringValueAllowed, .parameters = {.stringParameter = {.data = string, .length = sizeof(string) - 1}}}
#define CEIsDynamicStringAllowed(string, len) (CEQueryOperation_t){.opcode = CEDynamic(kCEOpStringValueAllowed), .parameters = {.dynamicParameter = {.data = string, .length = len}}}

/*!
 * @function CEIsStringPrefixAllowed
 * Returns an operation that will return a valid context if 1) the current context is a string and matches the prefix or 2) has an array that has the matches the prefix
 *
 * @param string
 * The string to match against (MUST BE A STRING LITERAL)
 *
 * @discussion
 * If a valid context is returned it will be in the same state as the execution context
 */
#define CEIsStringPrefixAllowed(string) (CEQueryOperation_t){.opcode = kCEOpStringPrefixValueAllowed, .parameters = {.stringParameter = {.data = string, .length = sizeof(string) - 1}}}
#define CEIsDynamicStringPrefixAllowed(string, len) (CEQueryOperation_t){.opcode = CEDynamic(kCEOpStringPrefixValueAllowed), .parameters = {.dynamicParameter = {.data = (const uint8_t*)(string), .length = len}}}

/*!
 * @function CEMatchData
 * Returns an operation that will return a valid context if and only if the context corresponds to valid data and matches the data exactly
 *
 * @param string
 * The data to match against (MUST BE A BYTE ARRAY)
 *
 * @discussion
 * If a valid context is returned it will be in the same state as the execution context
 */
#define CEMatchDynamicData(d, len) (CEQueryOperation_t){.opcode = CEDynamic(kCEOpMatchData), .parameters = {.dynamicParameter = {.data = d, .length = len}}}

/*!
 * @function CEIsDataAllowed
 * Returns an operation that will return a valid context if 1) the current context is data and allows the data, or 2) the context is an array of data elements that allows the data
 *
 * @param string
 * The data to match against (MUST BE A BYTE ARRAY)
 *
 * @discussion
 * If a valid context is returned it will be in the same state as the execution context
 */
#define CEIsDynamicDataAllowed(d, len) (CEQueryOperation_t){.opcode = CEDynamic(kCEOpMatchDataValueAllowed), .parameters = {.dynamicParameter = {.data = d, .length = len}}}

#pragma mark Helpers
/*
 Macro magic
 */
#define _SELECT_NTH_ARG(_1, _2, _3, _4, _5, _6, _7, _8, _9, N, ...) N

#define _mc_1(_call, x) _call(x),
#define _mc_2(_call, x, ...) _call(x), _mc_1(_call, __VA_ARGS__)
#define _mc_3(_call, x, ...) _call(x), _mc_2(_call, __VA_ARGS__)
#define _mc_4(_call, x, ...) _call(x), _mc_3(_call, __VA_ARGS__)
#define _mc_5(_call, x, ...) _call(x), _mc_4(_call, __VA_ARGS__)
#define _mc_6(_call, x, ...) _call(x), _mc_5(_call, __VA_ARGS__)
#define _mc_7(_call, x, ...) _call(x), _mc_6(_call, __VA_ARGS__)
#define _mc_8(_call, x, ...) _call(x), _mc_7(_call, __VA_ARGS__)
#define _mc_9(_call, x, ...) _call(x), _mc_8(_call, __VA_ARGS__)
#define _mc_10(_call, x, ...) _call(x), _mc_9(_call, __VA_ARGS__)

#define _MACRO_ITER(macro, ...) _SELECT_NTH_ARG(__VA_ARGS__, _mc_10, _mc_9, _mc_8 _mc_7, _mc_6, _mc_5, _mc_4, _mc_3, _mc_2, _mc_1)(macro, __VA_ARGS__)

/*!
 Macro to automatically generate a query path from a list of string sub components
 So
 @code
 CE_SELECT_PATH("hello, "world") will select a key "hello" and then look up "world" in the dictionary stored in the value of "hello"
 @endcode
 */
#define CE_SELECT_PATH(...) _MACRO_ITER(CESelectDictValue, __VA_ARGS__)

// Macro for string equals
#define CE_STRING_EQUALS(str) CEMatchString(str)

/*
 A macro that checks if the passed in context grants (via an explicit true boolean) the entitlement at the passed in path.
 */
#define CE_CONTEXT_GRANTS_ENTITLEMENT(ctx, ...) (CEContextQuery(ctx, (CEQuery_t){CE_SELECT_PATH(__VA_ARGS__) CEMatchBool(true)}, sizeof((CEQuery_t){CE_SELECT_PATH(__VA_ARGS__) CEMatchBool(true)}) / sizeof(CEQueryOperation_t)) == kCENoError)

#endif
STAGEEOF
    echo "Staged CoreEntitlements/QueryHelpers.h (no KDK)"
fi
if [ ! -f "EXTERNAL_HEADERS/CoreEntitlements/Result.h" ]; then
    mkdir -p "EXTERNAL_HEADERS/CoreEntitlements"
    cat > "EXTERNAL_HEADERS/CoreEntitlements/Result.h" <<'STAGEEOF'
//
//  Result.h
//  CoreEntitlements
//

#ifndef CORE_ENTITLEMENTS_RESULT_H
#define CORE_ENTITLEMENTS_RESULT_H

#ifndef _CE_INDIRECT
#error "Please include <CoreEntitlements/CoreEntitlements.h> instead of this file"
#endif

#include <sys/cdefs.h>
__ptrcheck_abi_assume_single();

#include <CoreEntitlements/Errors.h>
#include <stdint.h>

/*!
 * @function CEErrorPassThrough
 * Returns its argument. Convenient breakpoint location for when anything raises an error.
 */
static inline CEError_t CEErrorPassThrough(CEError_t E) {
    return E;
}

/*!
 * @function CE_CHECK
 * Checks if the passed in return value from one of CoreEntitlements function is an error, and if so returns that error in the current function
 */
#define CE_CHECK(ret) do { CEError_t _ce_error = ret; if (_ce_error != kCENoError) {return CEErrorPassThrough(_ce_error);} } while(0)

/*!
 * @function CE_THROW
 * Macro to "throw" (return) one of the CEErrors
 */
#define CE_THROW(err) return CEErrorPassThrough(err)

/*!
 * @function CE_OK
 * Returns a true if the passed in value corresponds to kCENoError
 */
#define CE_OK(ret) ((ret) == kCENoError)

#endif
STAGEEOF
    echo "Staged CoreEntitlements/Result.h (no KDK)"
fi
if [ ! -f "EXTERNAL_HEADERS/CoreEntitlements/Runtime.h" ]; then
    mkdir -p "EXTERNAL_HEADERS/CoreEntitlements"
    cat > "EXTERNAL_HEADERS/CoreEntitlements/Runtime.h" <<'STAGEEOF'
//
//  Runtime.h
//  CoreEntitlements
//
//

#ifndef CORE_ENTITLEMENTS_RUNTIME_H
#define CORE_ENTITLEMENTS_RUNTIME_H

#ifndef _CE_INDIRECT
#error "Please include <CoreEntitlements/CoreEntitlements.h> instead of this file"
#endif

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

__ptrcheck_abi_assume_single();

#define CE_MAX_KEY_SIZE 240

#ifndef __result_use_check
#define __result_use_check
#endif

#define CE_RUNTIME_VERSION 1
#define CE_RUNTIME_WITH_INDEX_VERSION 2

/*!
 * @struct CEBuffer
 * Represents a sized chunk of DER data
 * Strings and blobs used and returned by CoreEntitlements always use CEBuffer
 *
 * @note
 * If a DER string is returned to you via a CEBuffer, you cannot assume it is null-terminated.
 */
typedef struct {
    const uint8_t *__counted_by(length) data;
    size_t length;
} CEBuffer;

/*!
 * @struct CEStaticBuffer
 * Represents a sized chunk of data that is stored inline
 */
typedef struct {
    uint8_t data[CE_MAX_KEY_SIZE];
    size_t length;
} CEStaticBuffer;

#define CEBuffStr(str) (CEBuffer){.data = (const uint8_t*)str, .length = sizeof(str) - 1}

/*!
 * @typedef CERuntimeMalloc
 * Function prototype that the CERuntime may ues to allocate data (e.g.. malloc)
 */
typedef void* __unsafe_indexable (*CERuntimeMalloc)(const CERuntime_t rt, size_t size) __result_use_check;
/*!
 * @typedef CERuntimeFree
 * Function prototype that the CERuntime may ues to free allocated data (e.g. free)
 */
typedef void (*CERuntimeFree)(const CERuntime_t rt, void* address);
/*!
 * @typedef CERuntimeLog
 * Function prototype that the CERuntime may use to log helpful information (e.g. printf)
 */
typedef void (*CERuntimeLog)(const CERuntime_t rt, const char* __unsafe_indexable fmt, ...) __printflike(2, 3);
/*!
 * @typedef CERuntimeAbort
 * Function prototype that the CERuntime will use if it encounters a condition which may compromise the integrity of the system (e.g. abort, panic)
 */
typedef void (*CERuntimeAbort)(const CERuntime_t rt, const char* __unsafe_indexable fmt, ...) __printflike(2, 3) __attribute__((noreturn));
/*!
 * @typedef CERuntimeInternalStatus
 * Function prototype that the CERuntime may use to query AppleInternal status
 */
typedef bool (*CERuntimeInternalStatus)(const CERuntime_t rt);

/*!
 * @typedef CERuntimeAllocIndex
 * Function prototype that the CERuntime may ues to allocate an index of the specified size
 */
typedef void* __unsafe_indexable (*CERuntimeAllocIndex)(const CERuntime_t rt, size_t size) __result_use_check;

/*!
 * @typedef CERuntimeFreeIndex
 * Function prototype that the CERuntime may ues to free an index of the specified size
 */
typedef void (*CERuntimeFreeIndex)(const CERuntime_t rt, void* index, size_t size);

/*!
 * @struct CERuntime
 * This structure represents the interface that CoreEntitlements uses to communicate with the outside world.
 * The presense or absence of function pointers in this structure may degrade certain functionality.
 *
 * @note
 * The only prototype that MUST be implemented is CERuntimeAbort abort.
 */
struct CERuntime {
    const uint64_t                  version;
    const CERuntimeMalloc           alloc;
    const CERuntimeFree             free;
    const CERuntimeLog              log;
    const CERuntimeAbort            abort;
    const CERuntimeInternalStatus   internalStatus;
    const CERuntimeAllocIndex       allocIndex;
    const CERuntimeFreeIndex        freeIndex;
} ;

#endif
STAGEEOF
    echo "Staged CoreEntitlements/Runtime.h (no KDK)"
fi
if [ ! -f "EXTERNAL_HEADERS/CoreEntitlements/Serialization.h" ]; then
    mkdir -p "EXTERNAL_HEADERS/CoreEntitlements"
    cat > "EXTERNAL_HEADERS/CoreEntitlements/Serialization.h" <<'STAGEEOF'
//
//  Serialization.h
//  CoreEntitlements
//
//

#ifndef CORE_ENTITLEMENTS_SERIALIZATION_H
#define CORE_ENTITLEMENTS_SERIALIZATION_H

#ifndef _CE_INDIRECT
#error "Please include <CoreEntitlements/CoreEntitlements.h> instead of this file"
#endif

#include <CoreEntitlements/Result.h>
#include <CoreEntitlements/Runtime.h>
#include <CoreEntitlements/Entitlements.h>

__ptrcheck_abi_assume_single();

/*!
 * @enum CESerializedElementType_t
 * These are the primitive types that CoreEntitlements can serialize
 * Depending on the underlying representation some of these elements may be "virtual" or zero-sized.
 * However, they must still be included.
 */
OS_CLOSED_ENUM(CESerializedElementType, int64_t,
               /* A boolean element with a true / false value */
               kCESerializedBool = 1,
               /* A string element with a definite length */
               kCESerializedString = 2,
               /* A key string element with a definite length */
               kCESerializedKey = 3,
               /* An integer element, must be representable as int64_t */
               kCESerializedInteger = 4,
               /* Marks the start of an array / ordered sequence */
               kCESerializedArrayBegin = 5,
               /* Marks the end of an array / ordered sequence */
               kCESerializedArrayEnd = 6,
               /* Marks the start of a dictionary */
               /* The only valid elements contained in a dictionary are tuples (represented as an ordered sequence) */
               /* The first element of the ordered sequence must be kCESerializedString value */
               /* No restrictions are placed on the contents of the second element*/
               kCESerializedDictionaryBegin = 7,
               /* Marks the end of a dictionary */
               kCESerializedDictionaryEnd = 8,
               /* A data element with a definite length*/
               kCESerializedData = 9,
               );

/*!
 * @typedef CESerializedElement_t
 * This structure represents an encodable piece of data, along with its type and length (in bytes).
 * For the most part you will not need to use this structure manually, and instead you should use the helpers below
 */
typedef struct CESerializedElement {
    CESerializedElementType_t type;
    union {
#if !__has_ptrcheck
        void* bytes;
#endif
        int64_t value;
    } data;
    size_t length;
    bool pair;
} CESerializedElement_t;

static inline void *CE_HEADER_INDEXABLE CESerializedElementGetData(const CESerializedElement_t *element) {
    return __unsafe_forge_bidi_indexable(void *, element->data.value, element->length);
}

static inline void CESerializedElementSetData(CESerializedElement_t *element, void *__sized_by(length) bytes, size_t length) {
    element->data.value = (intptr_t)bytes;
    element->length = length;
}

/*!
 * @function CESizeSerialization
 * This function will iterate over the elements that are to be serialized and compute the size of an allocation that needs to be made
 * for a successful serialization.
 *
 * @note
 * This function may modify the length field of the CESerializedElements that are passed in. This must be done for serialization to succeed
 *
 * @returns
 * kCENoError if the requiredSize has been successfully populated and contains a valid value
 */
CEError_t CESizeSerialization(CESerializedElement_t elements[__counted_by(elementsCount)], size_t elementsCount, size_t* requiredSize) __result_use_check;

/*!
 * @function CESizeXMLSerialization
 * This function will iterate over the elements that are to be serialized and compute the size of an allocation that needs to be made
 * for a successful serialization to XML.
 *
 * @note
 * This function may modify the length field of the CESerializedElements that are passed in. This must be done for serialization to succeed
 *
 * @returns
 * kCENoError if the requiredSize has been successfully populated and contains a valid value
 */
CEError_t CESizeXMLSerialization(CESerializedElement_t elements[__counted_by(elementsCount)], size_t elementsCount, size_t* requiredSize) __result_use_check;

/*!
 * @function CESerializeWithOptions
 * Serializes the array of elements that contains the underlying data. The elements must have been sized with CESizeSerialization before calling this function.
 *
 * @param runtime
 * The runtime to use for this operation
 *
 * @param options
 * Options that modify what can be serialized.
 *
 * @param elements
 * The list of elements to serialize
 *
 * @param elementsCount
 * How many elements are in that list
 *
 * @param start
 * A pointer to the first byte into a buffer that will be filled with the serialized representation
 *
 * @param end
 * A pointer 1 byte past the end of the buffer to be used for serialization
 */
CEError_t CESerializeWithOptions(const CERuntime_t runtime, CEValidationOptions* options, CESerializedElement_t elements[__counted_by(elementsCount)], size_t elementsCount, uint8_t *__ended_by(end) start, uint8_t* end) __result_use_check;

/*!
 * @function CESerialize
 * Serializes the array of elements that contains the underlying data. The elements must have been sized with CESizeSerialization before calling this function.
 *
 * @param runtime
 * The runtime to use for this operation
 *
 * @param elements
 * The list of elements to serialize
 *
 * @param elementsCount
 * How many elements are in that list
 *
 * @param start
 * A pointer to the first byte into a buffer that will be filled with the serialized representation
 *
 * @param end
 * A pointer 1 byte past the end of the buffer to be used for serialization
 */
CEError_t CESerialize(const CERuntime_t runtime, CESerializedElement_t elements[__counted_by(elementsCount)], size_t elementsCount, uint8_t *__ended_by(end) start, uint8_t* end) __result_use_check;

/*!
 * @function CESerializeXML
 * Serializes the array of elements that contains the underlying data. The elements must have been sized with CESizeXMLSerialization before calling this function.
 *
 * @param runtime
 * The runtime to use for this operation
 *
 * @param elements
 * The list of elements to serialize
 *
 * @param elementsCount
 * How many elements are in that list
 *
 * @param start
 * A pointer to the first byte into a buffer that will be filled with the serialized representation
 *
 * @param end
 * A pointer 1 byte past the end of the buffer to be used for serialization
 */
CEError_t CESerializeXML(const CERuntime_t runtime, CESerializedElement_t elements[__counted_by(elementsCount)], size_t elementsCount, uint8_t *__ended_by(end) start, uint8_t* end) __result_use_check;

// Helpers
// These automatically construct CESerializedElements for you
#define CESerializeInteger(intv) (CESerializedElement_t){.type = kCESerializedInteger, .data.value = intv}
#define CESerializeBool(boolVal) (CESerializedElement_t){.type = kCESerializedBool, .data.value = !!boolVal}
#define CESerializeStaticString(strVal) (CESerializedElement_t){.type = kCESerializedString, .data.value = (intptr_t)strVal, .length = sizeof(strVal) - 1}
#define CESerializeKey(strVal) (CESerializedElement_t){.type = kCESerializedKey, .data.value = (intptr_t)strVal, .length = sizeof(strVal) - 1}
#define CESerializeDynamicKey(strVal, len) (CESerializedElement_t){.type = kCESerializedKey, .data.value = (intptr_t)strVal, .length = len}
#define CESerializeString(strVal, len) (CESerializedElement_t){.type = kCESerializedString, .data.value = (intptr_t)strVal, .length = len}
#define CESerializeData(dataVal, len) (CESerializedElement_t){.type = kCESerializedData, .data.value = (intptr_t)dataVal, .length = len}
#define CESerializeArray(...) (CESerializedElement_t){.type = kCESerializedArrayBegin}, __VA_ARGS__ , (CESerializedElement_t){.type = kCESerializedArrayEnd}
#define CESerializeDictionary(...) (CESerializedElement_t){.type = kCESerializedDictionaryBegin}, __VA_ARGS__ , (CESerializedElement_t){.type = kCESerializedDictionaryEnd}
#define CESerializeDictionaryPair(a, b) CESerializeArray(a, b)

#endif
STAGEEOF
    echo "Staged CoreEntitlements/Serialization.h (no KDK)"
fi
if [ ! -f "EXTERNAL_HEADERS/CoreEntitlements/der_vm.h" ]; then
    mkdir -p "EXTERNAL_HEADERS/CoreEntitlements"
    cat > "EXTERNAL_HEADERS/CoreEntitlements/der_vm.h" <<'STAGEEOF'
//
//  der_vm.h
//  CoreEntitlements
//

#ifndef CORE_ENTITLEMENTS_DER_VM_H
#define CORE_ENTITLEMENTS_DER_VM_H

#include <CoreEntitlements/CoreEntitlements.h>
#include <stdint.h>
#include <stdbool.h>

__ptrcheck_abi_assume_single();

// The kernel doesn't have access to this one
#if __has_include (<corecrypto/ccder.h>)
#include <corecrypto/ccder.h>
#else
typedef unsigned long ccder_tag;
#endif


/*!
 * @typedef der_vm_context_t
 * Represents the current execution state of the DERQL interpreter.
 * The context can be initialized with der_vm_context_create  and subsequently used in invocations of der_vm_execute.
 * This object is passed by value and the functions that operate on the der_vm_context_t do not modify it but instead return a copy.
 * As a consequence, the state of the interpreter can be captured at any execution point by holding on to the context.
 */
typedef struct der_vm_context {
    CERuntime_t runtime;
#if CE_ACCELERATION_SUPPORTED
    struct CEAccelerationContext lookup;
#endif
    ccder_tag dictionary_tag;
    bool sorted;
    bool valid;
    union {
        // the one you should use
        ccder_read_blob ccstate;
        
        // for compatibility
        struct {
            const uint8_t *__ended_by(der_end) der_start;
            const uint8_t *der_end;
        } state;
    };
} der_vm_context_t;

/*!
 * @function der_vm_context_create
 * Returns an initialized, valid,  der_vm_context_t against which query operations may be performed
 * @param rt
 * Active runtime
 * @param dictionary_tag
 * Which DER tag should be used when matching dictionaries
 * @param sorted_keys
 * Whether the VM can assume that the keys are sorted
 * @param der
 * Pointer to the start of a DER object
 * @param der_end
 * Pointer to one byte past the end of the DER object
 * @discussion
 * The caller must ensure that the memory pointed to by der remains valid as long as the der_vm_context_t is used.
 * The caller must ensure that the DER object has been validated.
 */
der_vm_context_t der_vm_context_create(const CERuntime_t rt, ccder_tag dictionary_tag, bool sorted_keys, const uint8_t *__ended_by(der_end) der, const uint8_t *der_end);

/*!
 * @function der_vm_execute
 * Returns a new context that is derived by applying the op to the passed in context
 *
 * @param context
 * Context to execute against
 *
 * @param op
 * An operation to be performed against the context
 * This op should be created by one of the CEMatch* or CESelect* functions
 *
 * @discussion
 * If the VM encounters:
 *      1. Invalid operation
 *      2. An operation that fails to execute
 *      3. Invalid state
 * The VM will attempt to return an invalid context.
 * If the VM encounters an operation that it does not understand, the runtime's abort function will be executed.
 */
der_vm_context_t der_vm_execute(const der_vm_context_t context, CEQueryOperation_t op);

/*!
 * @function der_vm_execute_nocopy
 * Returns a new context that is derived by applying the op to the passed in context
 *
 * @param context
 * Context to execute against
 *
 * @param op
 * An operation to be performed against the context
 * This op should be created by one of the CEMatch* or CESelect* functions
 * The operation may be modified after execution and should not be re-used
 *
 * @discussion
 * If the VM encounters:
 *      1. Invalid operation
 *      2. An operation that fails to execute
 *      3. Invalid state
 * The VM will attempt to return an invalid context.
 * If the VM encounters an operation that it does not understand, the runtime's abort function will be executed.
 */
der_vm_context_t der_vm_execute_nocopy(const der_vm_context_t context, const CEQueryOperation_t* op);

/*!
 * @function der_vm_execute_seq_nocopy
 * Returns a new context that is derived by applying the operation sequence to the passed in context
 *
 * @param context
 * Context to execute against
 *
 * @param query
 * Operations to be performed against the context, see der_vm_execute_nocopy for more
 *
 * @param queryLength
 * Number of operations in the query
 *
 */
der_vm_context_t der_vm_execute_seq_nocopy(const der_vm_context_t context, const CEQueryOperation_t *__counted_by(queryLength) query, size_t queryLength);

/*!
 * @typedef der_vm_iteration_context
 * Iteration context that gets passed in on every call
 *
 * @field original
 * The original DER VM context (the container over which we are iterating)
 *
 * @field active
 * The actively selected DER VM context (i.e. the value)
 *
 * @field parent_type
 * The type of object being iterated over (dictionary or array)
 *
 * @field active_type
 * The type of the selected object
 *
 * @field user_data
 * The object you passed in the call to der_vm_iterate
 */
typedef struct {
    der_vm_context_t original;
    der_vm_context_t active;
    CEType_t parent_type;
    CEType_t active_type;
    void* user_data;
} der_vm_iteration_context;

/*!
 * @typedef der_vm_iteration_callback
 *
 * @brief Function definition for the callback that der_vm_iterate uses
 *
 * @param ctx The information about the iterable is stored here
 */
typedef bool (*der_vm_iteration_callback)(der_vm_iteration_context ctx);



/*!
 * @function der_vm_iterate
 * @brief Iterates over a DER container, caliing the callback for every element
 *
 * @param context The context that points to a container
 * @param user_data This will be passed in verbatim in the der_vm_iteration_context
 * @param callback This function is called for every element
 *
 * @returns kCENoError if the function exited normally
 */
CEError_t der_vm_iterate(const der_vm_context_t context, void* user_data, der_vm_iteration_callback callback);

#ifdef __BLOCKS__
/*!
 * @typedef der_vm_iteration_block
 *
 * @brief Function definition for the callback that der_vm_iterate_b uses
 *
 * @param ctx The information about the iterable is stored here, you may modify it
 */
typedef bool (^der_vm_iteration_block)(der_vm_iteration_context* ctx);

/*!
 * @function der_vm_iterate_b
 * @brief Iterates over a DER container, calling the block for every element
 * @note dev_vm_iterate is implemented using the block interface. Using this function directly is more efficient.
 * @param context The context that points to a container
 * @param callback This block is called for every element
 *
 * @returns kCENoError if the function exited normally
 */
CEError_t der_vm_iterate_b(const der_vm_context_t* context, der_vm_iteration_block callback);
#endif

/*!
 * @function der_vm_context_is_valid
 * Returns a boolean indication if a particular context is valid
 *
 * @param context
 * The context in question
 *
 * @discussion
 * It is generally safe to execute any operation against an invalid context
 * However the resulting context will also be invalid
 */
bool der_vm_context_is_valid(const der_vm_context_t context);

/*!
 * @function der_vm_CEType_from_context
 * Returns a CEType_t corresponding to the item currently pointed to by the context's DER state
 *
 * @param context
 * The context in question
 * @param tag
 * Nullable pointer to where to store the decoded DER tag
 */
CEType_t der_vm_CEType_from_context(const der_vm_context_t context, ccder_tag* tag);

/*!
 * @function der_vm_CEType_from_ccder_tag
 * Returns a CEType_t corresponding to the tag value, without touching the context's DER state
 *
 * @param context
 * The context in question
 * @param tag
 * Nullable pointer to where to store the decoded DER tag
 */
CEType_t der_vm_CEType_from_ccder_tag(const der_vm_context_t context, ccder_tag tag);

/*!
 * @function der_vm_integer_from_context
 * Returns the number selected by the current context
 */
int64_t der_vm_integer_from_context(const der_vm_context_t context);

/*!
 * @function der_vm_string_from_context
 * Returns the string selected by the current context
 */
CEBuffer der_vm_string_from_context(const der_vm_context_t context);

/*!
 * @function der_vm_bool_from_context
 * Returns the bool selected by the current context
 */
bool der_vm_bool_from_context(const der_vm_context_t context);

/*!
 * @function der_vm_data_from_context
 * Returns the data selected by the current context
 */
CEBuffer der_vm_data_from_context(const der_vm_context_t context);

/*!
 * @function der_vm_buffer_from_context
 * Returns the content described by the tag in the context
 */
CEBuffer der_vm_buffer_from_context(const der_vm_context_t context);

/*!
 * @function CEBuffer_cmp
 * Does a memcmp like match between two CEBuffers
 */
int CEBuffer_cmp(const CEBuffer left, const CEBuffer right);

#endif
STAGEEOF
    echo "Staged CoreEntitlements/der_vm.h (no KDK)"
fi
if [ ! -f "EXTERNAL_HEADERS/img4/4xnu.h" ]; then
    mkdir -p "EXTERNAL_HEADERS/img4"
    cat > "EXTERNAL_HEADERS/img4/4xnu.h" <<'STAGEEOF'
/*!
 * @header
 * xnu-specific interfaces. These are hacks that only exist because xnu doesn't
 * like linking static libraries, and we have a pre-existing contract for how to
 * export our interfaces to xnu.
 */
#ifndef __IMG4_4XNU_H
#define __IMG4_4XNU_H

#ifndef __IMG4_INDIRECT
#error "Please #include <img4/firmware.h> instead of this file directly"
#endif // __IMG4_INDIRECT

__BEGIN_DECLS
OS_ASSUME_NONNULL_BEGIN

/*!
 * @function img4_get_manifest
 * Returns a buffer representing the Image4 manifest bytes within the given DER
 * blob.
 *
 * @param buff
 * The buffer to examine for the Image4 manifest.
 *
 * @param len
 * The length of {@link buff}.
 *
 * @param buff_storage
 * Upon successful return, a buffer object which will contain a pointer to and
 * the length of the Image4 manifest.
 *
 * @result
 * Upon success, {@link buff_storage} is returned. If the DER blob contains no
 * Image4 manifest, then NULL is returned.
 */
#if !XNU_KERNEL_PRIVATE
IMG4_API_AVAILABLE_20211105
OS_EXPORT OS_WARN_RESULT OS_NONNULL1 OS_NONNULL3
const img4_buff_t *
img4_get_manifest(const void *buff, size_t len, img4_buff_t *buff_storage);
#else
#define img4_get_manifest(...) \
		(img4if->i4if_v15.get_manifest(__VA_ARGS__))
#endif

/*!
 * @function img4_get_payload
 * Returns a buffer representing the Image4 payload bytes within the given DER
 * blob.
 *
 * @param buff
 * The buffer to examine for the Image4 payload.
 *
 * @param len
 * The length of {@link buff}.
 *
 * @param buff_storage
 * Upon successful return, a buffer object which will contain a pointer to and
 * the length of the Image4 manifest.
 *
 * @result
 * Upon success, {@link buff_storage} is returned. If the DER blob contains no
 * Image4 payload, then NULL is returned.
 */
#if !XNU_KERNEL_PRIVATE
IMG4_API_AVAILABLE_20211105
OS_EXPORT OS_WARN_RESULT OS_NONNULL1 OS_NONNULL3
const img4_buff_t *
img4_get_payload(const void *buff, size_t len, img4_buff_t *buff_storage);
#else
#define img4_get_payload(...) \
		(img4if->i4if_v15.get_payload(__VA_ARGS__))
#endif

OS_ASSUME_NONNULL_END
__END_DECLS

#endif // __IMG4_4XNU_H
STAGEEOF
    echo "Staged img4/4xnu.h (no KDK)"
fi
if [ ! -f "EXTERNAL_HEADERS/img4/api.h" ]; then
    mkdir -p "EXTERNAL_HEADERS/img4"
    cat > "EXTERNAL_HEADERS/img4/api.h" <<'STAGEEOF'
/*!
 * @header
 * API definitions.
 */
#ifndef __IMG4_API_H
#define __IMG4_API_H

#ifndef __IMG4_INDIRECT
#error "Please #include <img4/firmware.h> instead of this file directly"
#endif // __IMG4_INDIRECT

#include <img4/shim.h>

/*!
 * @const IMG4_API_VERSION
 * The API version of the library. This version will be changed in accordance
 * with new API introductions so that callers may submit code to the build that
 * adopts those new APIs before the APIs land by using the following pattern:
 *
 *     #if IMG4_API_VERSION >= 20180424
 *     img4_new_api();
 *     #endif
 *
 * In this example, the library maintainer and API adopter agree on an API
 * version of 20180424 ahead of time for the introduction of
 * img4_new_api(). When a libdarwin with that API version is submitted, the
 * project is rebuilt, and the new API becomes active.
 *
 * Breaking API changes will be both covered under this mechanism as well as
 * individual preprocessor macros in this header that declare new behavior as
 * required.
 *
 * @note
 * For a period of time, the API version was incorrectly defined as 20212105
 * when it should have been 20210521. Avoid version comparisons across that
 * version epoch.
 */
#define IMG4_API_VERSION (20220513u)

#if IMG4_TARGET_DARWIN
#define IMG4_API_AVAILABLE_FALL_2018 \
		API_AVAILABLE( \
			macos(10.15), \
			ios(12.0), \
			tvos(12.0), \
			watchos(5.0))

#define IMG4_API_DEPRECATED_FALL_2018 \
		API_DEPRECATED_WITH_REPLACEMENT( \
			"img4_firmware_t", \
			macos(10.15, 11.0), \
			ios(12.2, 14.0), \
			tvos(12.2, 14.0), \
			watchos(5.2, 7.0))

#define IMG4_API_AVAILABLE_SPRING_2019 \
		API_AVAILABLE(\
			macos(10.15), \
			ios(12.2), \
			tvos(12.2), \
			watchos(5.2))

#define IMG4_API_AVAILABLE_FALL_2020 \
		API_AVAILABLE( \
			macos(11.0), \
			ios(14.0), \
			tvos(14.0), \
			watchos(7.0), \
			bridgeos(5.0))

#define IMG4_API_AVAILABLE_FALL_2021 \
		API_AVAILABLE( \
			macos(12.0), \
			ios(15.0), \
			tvos(15.0), \
			watchos(8.0), \
			bridgeos(6.0))

#define IMG4_API_AVAILABLE_FALL_2021_B \
		API_AVAILABLE( \
			macos(12.1), \
			ios(15.1), \
			tvos(15.1), \
			watchos(8.1), \
			bridgeos(6.1))
#define IMG4_API_AVAILABLE_FALL_2022 \
		API_AVAILABLE( \
			macos(13.0), \
			ios(16.0), \
			tvos(16.0), \
			watchos(9.0), \
			bridgeos(7.0))
#else
#define IMG4_API_AVAILABLE_FALL_2018
#define IMG4_API_DEPRECATED_FALL_2018
#define IMG4_API_AVAILABLE_SPRING_2019
#define IMG4_API_AVAILABLE_FALL_2020
#define IMG4_API_AVAILABLE_FALL_2021
#define IMG4_API_AVAILABLE_FALL_2021_B
#define IMG4_API_AVAILABLE_FALL_2022
#endif

#define IMG4_API_AVAILABLE_20180112 IMG4_API_AVAILABLE_FALL_2018
#define IMG4_API_AVAILABLE_20181106 IMG4_API_AVAILABLE_SPRING_2019
#define IMG4_API_AVAILABLE_20200508 IMG4_API_AVAILABLE_FALL_2020
#define IMG4_API_AVAILABLE_20200608 IMG4_API_AVAILABLE_FALL_2020
#define IMG4_API_AVAILABLE_20200724 IMG4_API_AVAILABLE_FALL_2020
#define IMG4_API_AVAILABLE_20210113 IMG4_API_AVAILABLE_FALL_2021
#define IMG4_API_AVAILABLE_20210205 IMG4_API_AVAILABLE_FALL_2021
#define IMG4_API_AVAILABLE_20210226 IMG4_API_AVAILABLE_FALL_2021
#define IMG4_API_AVAILABLE_20210305 IMG4_API_AVAILABLE_FALL_2021
#define IMG4_API_AVAILABLE_20210521 IMG4_API_AVAILABLE_FALL_2021
#define IMG4_API_AVAILABLE_20210624 IMG4_API_AVAILABLE_FALL_2021
#define IMG4_API_AVAILABLE_20210731 IMG4_API_AVAILABLE_FALL_2021_B
#define IMG4_API_AVAILABLE_20211105 IMG4_API_AVAILABLE_FALL_2022
#define IMG4_API_AVAILABLE_20211112 IMG4_API_AVAILABLE_FALL_2022
#define IMG4_API_AVAILABLE_20211119 IMG4_API_AVAILABLE_FALL_2022
#define IMG4_API_AVAILABLE_20211126 IMG4_API_AVAILABLE_FALL_2022
#define IMG4_API_AVAILABLE_20211224 IMG4_API_AVAILABLE_FALL_2022
#define IMG4_API_AVAILABLE_20220128 IMG4_API_AVAILABLE_FALL_2022
#define IMG4_API_AVAILABLE_20220322 IMG4_API_AVAILABLE_FALL_2022
#define IMG4_API_AVAILABLE_20220401 IMG4_API_AVAILABLE_FALL_2022
#define IMG4_API_AVAILABLE_20220513 IMG4_API_AVAILABLE_FALL_2022

/*!
 * @typedef img4_struct_version_t
 * A type describing the version of a structure in the library.
 */
IMG4_API_AVAILABLE_20180112
typedef uint16_t img4_struct_version_t;

#endif // __IMG4_API_H
STAGEEOF
    echo "Staged img4/api.h (no KDK)"
fi
if [ ! -f "EXTERNAL_HEADERS/img4/chip.h" ]; then
    mkdir -p "EXTERNAL_HEADERS/img4"
    cat > "EXTERNAL_HEADERS/img4/chip.h" <<'STAGEEOF'
/*!
 * @header
 * Supported chip environments.
 */
#ifndef __IMG4_CHIP_H
#define __IMG4_CHIP_H

#ifndef __IMG4_INDIRECT
#error "Please #include <img4/firmware.h> instead of this file directly"
#endif // __IMG4_INDIRECT

OS_ASSUME_NONNULL_BEGIN

/*!
 * @typedef img4_chip_select_array_t
 * A type representing a list of chips from which the implementation may select.
 */
IMG4_API_AVAILABLE_20200724
typedef const img4_chip_t *_Nullable const *img4_chip_select_array_t;

/*!
 * @const IMG4_CHIP_INSTANCE_STRUCT_VERSION
 * The version of the {@link img4_chip_instance_t} supported by the
 * implementation.
 */
#define IMG4_CHIP_INSTANCE_STRUCT_VERSION (6u)

/*!
 * @typedef img4_chip_instance_omit_t
 * A bitfield describing omitted identifiers from a chip instance.
 *
 * @const IMG4_CHIP_INSTANCE_OMIT_CEPO
 * The chip instance has no epoch.
 *
 * @const IMG4_CHIP_INSTANCE_OMIT_BORD
 * The chip instance has no board identifier.
 *
 * @const IMG4_CHIP_INSTANCE_OMIT_CHIP
 * The chip instance has no chip identifier.
 *
 * @const IMG4_CHIP_INSTANCE_OMIT_SDOM
 * The chip instance has no security domain.
 *
 * @const IMG4_CHIP_INSTANCE_OMIT_ECID
 * The chip instance has no unique chip identifier.
 *
 * @const IMG4_CHIP_INSTANCE_OMIT_CPRO
 * The chip instance has no certificate production status.
 *
 * @const IMG4_CHIP_INSTANCE_OMIT_CSEC
 * The chip instance has no certificate security mode.
 *
 * @const IMG4_CHIP_INSTANCE_OMIT_EPRO
 * The chip instance has no effective production status.
 *
 * @const IMG4_CHIP_INSTANCE_OMIT_ESEC
 * The chip instance has no effective security mode.
 *
 * @const IMG4_CHIP_INSTANCE_OMIT_IUOU
 * The chip instance has no internal-use-only-unit property.
 *
 * @const IMG4_CHIP_INSTANCE_OMIT_RSCH
 * The chip instance has no research fusing state.
 *
 * @const IMG4_CHIP_INSTANCE_OMIT_EUOU
 * The chip instance has no engineering-use-only-unit property.
 *
 * @const IMG4_CHIP_INSTANCE_OMIT_ESDM
 * The chip instance has no extended security domain property.
 *
 * @const IMG4_CHIP_INSTANCE_OMIT_FPGT
 * The chip instance has no factory pre-release global trust property.
 *
 * @const IMG4_CHIP_INSTANCE_OMIT_UDID
 * The chip instance has no universal device identifier property.
 *
 * @const IMG4_CHIP_INSTANCE_OMIT_FCHP
 * The chip instance has no cryptex chip identifier property.
 *
 * @const IMG4_CHIP_INSTANCE_OMIT_TYPE
 * The chip instance has no cryptex type identifier property.
 *
 * @const IMG4_CHIP_INSTANCE_OMIT_STYP
 * The chip instance has no cryptex subtype identifier property.
 *
 * @const IMG4_CHIP_INSTANCE_OMIT_CLAS
 * The chip instance has no product class property.
 */
OS_CLOSED_OPTIONS(img4_chip_instance_omit, uint64_t,
	IMG4_CHIP_INSTANCE_OMIT_CEPO = (1 << 0),
	IMG4_CHIP_INSTANCE_OMIT_BORD = (1 << 1),
	IMG4_CHIP_INSTANCE_OMIT_CHIP = (1 << 2),
	IMG4_CHIP_INSTANCE_OMIT_SDOM = (1 << 3),
	IMG4_CHIP_INSTANCE_OMIT_ECID = (1 << 4),
	IMG4_CHIP_INSTANCE_OMIT_CPRO = (1 << 5),
	IMG4_CHIP_INSTANCE_OMIT_CSEC = (1 << 6),
	IMG4_CHIP_INSTANCE_OMIT_EPRO = (1 << 7),
	IMG4_CHIP_INSTANCE_OMIT_ESEC = (1 << 8),
	IMG4_CHIP_INSTANCE_OMIT_IUOU = (1 << 9),
	IMG4_CHIP_INSTANCE_OMIT_RSCH = (1 << 10),
	IMG4_CHIP_INSTANCE_OMIT_EUOU = (1 << 11),
	IMG4_CHIP_INSTANCE_OMIT_ESDM = (1 << 12),
	IMG4_CHIP_INSTANCE_OMIT_FPGT = (1 << 13),
	IMG4_CHIP_INSTANCE_OMIT_UDID = (1 << 14),
	IMG4_CHIP_INSTANCE_OMIT_FCHP = (1 << 15),
	IMG4_CHIP_INSTANCE_OMIT_TYPE = (1 << 16),
	IMG4_CHIP_INSTANCE_OMIT_STYP = (1 << 17),
	IMG4_CHIP_INSTANCE_OMIT_CLAS = (1 << 18),
);

/*!
 * @typedef img4_chip_instance_t
 * An structure describing an instance of a chip.
 *
 * @field chid_version
 * The version of the structure. Initialize to
 * {@link IMG4_CHIP_INSTANCE_STRUCT_VERSION}.
 *
 * @field chid_chip_family
 * The chip family of which this is an instance.
 *
 * @field chid_omit
 * The identifiers which are absent from the chip instance.
 *
 * @field chid_cepo
 * The certificate epoch of the chip instance.
 *
 * @field chid_bord
 * The board identifier of the chip instance.
 *
 * @field chid_chip
 * The chip identifier of the chip instance.
 *
 * @field chid_sdom
 * The security domain of the chip instance.
 *
 * @field chid_ecid
 * The unique chip identifier of the chip instance.
 *
 * @field chid_cpro
 * The certificate production status of the chip instance.
 *
 * @field chid_csec
 * The certificate security mode of the chip instance.
 *
 * @field chid_epro
 * The effective production status of the chip instance.
 *
 * @field chid_esec
 * The effective security mode of the chip instance.
 *
 * @field chid_iuou
 * The internal use-only unit status of the chip instance.
 *
 * @field chid_rsch
 * The research mode of the chip instance.
 *
 * @field chid_euou
 * The engineering use-only unit status of the chip instance.
 *
 * Added in version 1 of the structure.
 *
 * @field chid_esdm
 * The extended security domain of the chip instance.
 *
 * Added in version 3 of the structure.
 *
 * @field chid_fpgt
 * The factory pre-release global trust status of the chip instance.
 *
 * Added in version 4 of the structure.
 *
 * @field chid_udid
 * The universal device identifier of the chip instance.
 *
 * Added in version 5 of the structure.
 *
 * @const chid_fchp
 * The cryptex chip identifier of the chip instance.
 *
 * Added in version 6 of the structure.
 *
 * @const chid_type
 * The cryptex type identifier of the chip instance.
 *
 * Added in version 6 of the structure.
 *
 * @const chid_styp
 * The cryptex subtype identifier of the chip instance.
 *
 * Added in version 6 of the structure.
 *
 * @field chid_clas
 * The product class of the chip instance.
 *
 * Added in version 6 of the structure.
 */
IMG4_API_AVAILABLE_20200508
typedef struct _img4_chip_instance {
	img4_struct_version_t chid_version;
	const img4_chip_t *chid_chip_family;
	img4_chip_instance_omit_t chid_omit;
	uint32_t chid_cepo;
	uint32_t chid_bord;
	uint32_t chid_chip;
	uint32_t chid_sdom;
	uint64_t chid_ecid;
	bool chid_cpro;
	bool chid_csec;
	bool chid_epro;
	bool chid_esec;
	bool chid_iuou;
	bool chid_rsch;
	bool chid_euou;
	uint32_t chid_esdm;
	bool chid_fpgt;
	img4_dgst_t chid_udid;
	uint32_t chid_fchp;
	uint32_t chid_type;
	uint32_t chid_styp;
	uint32_t chid_clas;
} img4_chip_instance_t;

/*!
 * @function IMG4_CHIP_INSTANCE_INIT
 * A convenience initializer which can be used to initialize a chip instance to
 * a given family.
 *
 * @param _family
 * The family of chip.
 *
 * @result
 * A fully-initialized structure of the appropriate version supported by the
 * implementation. The resulting chip instance omits no identifiers.
 */
#define IMG4_CHIP_INSTANCE_INIT(_family) (img4_chip_instance_t){ \
	.chid_version = IMG4_CHIP_INSTANCE_STRUCT_VERSION, \
	.chid_chip_family = (_family), \
	.chid_omit = 0, \
	.chid_cepo = 0, \
	.chid_bord = 0, \
	.chid_chip = 0, \
	.chid_sdom = 0, \
	.chid_ecid = 0, \
	.chid_cpro = false, \
	.chid_csec = false, \
	.chid_epro = false, \
	.chid_esec = false, \
	.chid_iuou = false, \
	.chid_rsch = false, \
	.chid_euou = false, \
	.chid_esdm = 0, \
	.chid_fpgt = false, \
	.chid_udid = {0}, \
	.chid_fchp = 0, \
	.chid_type = 0, \
	.chid_styp = 0, \
	.chid_clas = 0, \
}

/*!
 * @function img4_chip_init_from_buff
 * Initializes a buffer as a chip object.
 *
 * @param buff
 * A pointer to the storage to use for the chip object.
 *
 * @param len
 * The size of the buffer.
 *
 * @discussion
 * The caller is expected to pass a buffer that is "big enough". If the provided
 * buffer is too small, the implementation will abort the caller.
 *
 * @example
 *
 *     uint8_t _buff[IMG4_CHIP_SIZE_RECOMMENDED];
 *     img4_chip_t *chip = NULL;
 *
 *     chip = img4_chip_init_from_buff(_buff, sizeof(_buff));
 */
#if !XNU_KERNEL_PRIVATE
IMG4_API_AVAILABLE_20200508
OS_EXPORT OS_WARN_RESULT OS_NONNULL1
img4_chip_t *
img4_chip_init_from_buff(void *buff, size_t len);
#else
#define img4_chip_init_from_buff (img4if->i4if_v7.chip_init_from_buff)
#endif

/*!
 * @function img4_chip_select_personalized_ap
 * Returns the chip appropriate for personalized verification against the host
 * AP.
 *
 * @result
 * The personalized chip environment for the host which corresponds to its
 * silicon identity.
 */
#if !XNU_KERNEL_PRIVATE
IMG4_API_AVAILABLE_20200508
OS_EXPORT OS_WARN_RESULT
const img4_chip_t *
img4_chip_select_personalized_ap(void);
#else
#define img4_chip_select_personalized_ap(...) \
		(img4if->i4if_v7.chip_select_personalized_ap(__VA_ARGS__))
#endif

/*!
 * @function img4_chip_select_personalized_sep
 * Returns the chip appropriate for personalized verification against the host
 * SEP.
 *
 * @result
 * The personalized chip environment for the host's SEP which corresponds to its
 * silicon identity. This will return NULL when called outside of the SEP
 * runtime.
 */
#if !XNU_KERNEL_PRIVATE
IMG4_API_AVAILABLE_20211119
OS_EXPORT OS_WARN_RESULT
const img4_chip_t *_Nullable
img4_chip_select_personalized_sep(void);
#else
#define img4_chip_select_personalized_sep(...) \
		(img4if->i4if_v16.chip_select_personalized_sep(__VA_ARGS__))
#endif

/*!
 * @function img4_chip_select_categorized_ap
 * Returns the chip appropriate for categorized verification against the host
 * AP.
 *
 * @result
 * The categorized chip environment for the host which corresponds to its
 * silicon identity. If the host has no AP category defined for it, NULL will be
 * returned.
 *
 * @discussion
 * Categorized chip environments have been scuttled and were never used. Please
 * remove all uses of this function.
 */
#if !XNU_KERNEL_PRIVATE
IMG4_API_AVAILABLE_20210305
OS_EXPORT OS_WARN_RESULT
const img4_chip_t *_Nullable
img4_chip_select_categorized_ap(void);
#else
#define img4_chip_select_categorized_ap(...) \
		(img4if->i4if_v12.chip_select_categorized_ap(__VA_ARGS__))
#endif

/*!
 * @function img4_chip_select_effective_ap
 * Returns the chip appropriate for verification against the host AP.
 *
 * @result
 * The currently enforced chip environment for the host. This interface is
 * generally only useful on the AP.
 */
#if !XNU_KERNEL_PRIVATE
IMG4_API_AVAILABLE_20200508
OS_EXPORT OS_WARN_RESULT
const img4_chip_t *
img4_chip_select_effective_ap(void);
#else
#define img4_chip_select_effective_ap(...) \
		(img4if->i4if_v7.chip_select_effective_ap(__VA_ARGS__))
#endif

/*!
 * @function img4_chip_select_cryptex1_boot
 * Returns the appropriate Cryptex1 boot chip environment for the currently-
 * booted effective AP environment.
 *
 * @result
 * The chip environment to use for verification.
 */
#if !XNU_KERNEL_PRIVATE
IMG4_API_AVAILABLE_20211126
OS_EXPORT OS_WARN_RESULT
const img4_chip_t *
img4_chip_select_cryptex1_boot(void);
#else
#define img4_chip_select_cryptex1_boot(...) \
		(img4if->i4if_v17.chip_select_cryptex1_boot(__VA_ARGS__))
#endif

/*!
 * @function img4_chip_select_cryptex1_preboot
 * Returns the appropriate Cryptex1 pre-reboot chip environment for the
 * currently-booted effective AP environment.
 *
 * @result
 * The chip environment to use for verification.
 */
#if !XNU_KERNEL_PRIVATE
IMG4_API_AVAILABLE_20211126
OS_EXPORT OS_WARN_RESULT
const img4_chip_t *
img4_chip_select_cryptex1_preboot(void);
#else
#define img4_chip_select_cryptex1_preboot(...) \
		(img4if->i4if_v17.chip_select_cryptex1_preboot(__VA_ARGS__))
#endif

/*!
 * @function img4_chip_get_cryptex1_boot
 * Returns the appropriate Cryptex1 boot chip environment associated with a
 * given AP environment.
 *
 * @param chip
 * The AP environment for which to obtain the associated Cryptex1 environment.
 *
 * @result
 * The Cryptex1 chip environment associated with {@link chip}. If there is no
 * Cryptex1 association, NULL is returned.
 */
#if !XNU_KERNEL_PRIVATE
IMG4_API_AVAILABLE_20220401
OS_EXPORT OS_WARN_RESULT OS_NONNULL1
const img4_chip_t *_Nullable
img4_chip_get_cryptex1_boot(const img4_chip_t *chip);
#else
#define img4_chip_get_cryptex1_boot(...) \
		(img4if->i4if_v18.chip_get_cryptex1_boot(__VA_ARGS__))
#endif

/*!
 * @function img4_chip_get_cryptex1_boot_proposal
 * Returns the appropriate Cryptex1 boot proposal chip environment associated
 * with a given AP environment.
 *
 * @param chip
 * The AP environment for which to obtain the associated Cryptex1 proposal
 * environment.
 *
 * @result
 * The Cryptex1 proposal chip environment associated with {@link chip}. If
 * there is no Cryptex1 association, NULL is returned.
 */
#if !XNU_KERNEL_PRIVATE
IMG4_API_AVAILABLE_20220401
OS_EXPORT OS_WARN_RESULT OS_NONNULL1
const img4_chip_t *_Nullable
img4_chip_get_cryptex1_boot_proposal(const img4_chip_t *chip);
#else
#define img4_chip_get_cryptex1_boot_proposal(...) \
		(img4if->i4if_v18.chip_get_cryptex1_boot_proposal(__VA_ARGS__))
#endif

/*!
 * @function img4_chip_instantiate
 * Returns an instantiation of the given chip using the default runtime where
 * necessary.
 *
 * @param chip
 * The chip to instantiate.
 *
 * @param chip_instance
 * Upon successful return, storage to be populated with the instantiated chip.
 * Upon failure, the contents of this storage are undefined.
 *
 * @result
 * Upon success, zero is returned. Otherwise, one of the following error codes
 * will be returned:
 *
 *     [EXDEV]       There was an error querying the runtime's identity oracle
 *     [ENODATA]     The expected property in the runtime's identity oracle was
 *                   of an unexpected type
 *     [EOVERFLOW]   The expected property in the runtime's identity oracle had
 *                   a value that was too large to be represented in the
 *                   expected type
 */
#if !XNU_KERNEL_PRIVATE
IMG4_API_AVAILABLE_20200508
OS_EXPORT OS_WARN_RESULT OS_NONNULL1 OS_NONNULL2
errno_t
img4_chip_instantiate(const img4_chip_t *chip,
		img4_chip_instance_t *chip_instance);
#else
#define img4_chip_instantiate(...) \
		(img4if->i4if_v7.chip_instantiate(__VA_ARGS__))
#endif

/*!
 * @function img4_chip_custom
 * Returns a custom chip derived from the given chip instance. The
 * {@link chid_chip_family} field of the given instance will be used as a
 * template from which to derive the new chip.
 *
 * @param chip_instance
 * The instance of the custom chip.
 *
 * The memory referenced by this pointer must be static or otherwise guaranteed
 * to be valid for the duration of the caller's use of the custom chip.
 *
 * @param chip
 * A pointer to storage for the new custom chip.
 *
 * The memory referenced by this pointer must be static or otherwise guaranteed
 * to be valid for the duration of the caller's use of the custom chip.
 *
 * This pointer should be obtained as the result of a call to
 * {@link img4_chip_init_from_buff}.
 *
 * @result
 * A new custom chip.
 */
#if !XNU_KERNEL_PRIVATE
IMG4_API_AVAILABLE_20200508
OS_EXPORT OS_WARN_RESULT OS_NONNULL1
const img4_chip_t *
img4_chip_custom(const img4_chip_instance_t *chip_instance, img4_chip_t *chip);
#else
#define img4_chip_custom(...) (img4if->i4if_v7.chip_custom(__VA_ARGS__))
#endif

OS_ASSUME_NONNULL_END

#endif // __IMG4_CHIP_H
STAGEEOF
    echo "Staged img4/chip.h (no KDK)"
fi
if [ ! -f "EXTERNAL_HEADERS/img4/chip_ap.h" ]; then
    mkdir -p "EXTERNAL_HEADERS/img4"
    cat > "EXTERNAL_HEADERS/img4/chip_ap.h" <<'STAGEEOF'
/*!
 * @header
 * AP chip environments.
 */
#ifndef __IMG4_CHIP_AP_H
#define __IMG4_CHIP_AP_H

#ifndef __IMG4_INDIRECT
#error "Please #include <img4/firmware.h> instead of this file directly"
#endif // __IMG4_INDIRECT

OS_ASSUME_NONNULL_BEGIN

/*!
 * @const IMG4_CHIP_AP_SHA1
 * The Application Processor on an Apple ARM SoC with an embedded sha1
 * certifcate chain.
 *
 * This chip environment represents one unique instance of such a chip.
 */
#if !XNU_KERNEL_PRIVATE
IMG4_API_AVAILABLE_20200508
OS_EXPORT
const img4_chip_t _img4_chip_ap_sha1;
#define IMG4_CHIP_AP_SHA1 (&_img4_chip_ap_sha1)
#else
#define IMG4_CHIP_AP_SHA1 (img4if->i4if_v7.chip_ap_sha1)
#endif

/*!
 * @const IMG4_CHIP_AP_SHA2_384
 * The Application Processor on an Apple ARM SoC with an embedded sha2-384
 * certifcate chain.
 *
 * This chip environment represents one unique instance of such a chip.
 */
#if !XNU_KERNEL_PRIVATE
IMG4_API_AVAILABLE_20200508
OS_EXPORT
const img4_chip_t _img4_chip_ap_sha2_384;
#define IMG4_CHIP_AP_SHA2_384 (&_img4_chip_ap_sha2_384)
#else
#define IMG4_CHIP_AP_SHA2_384 (img4if->i4if_v7.chip_ap_sha2_384)
#endif

/*!
 * @const IMG4_CHIP_AP_HYBRID
 * An Intel x86 processor whose chain of trust is rooted in an instance of a
 * {@link IMG4_CHIP_AP_SHA2_384} chip. Firmwares executed on this chip are
 * authenticated against the characteristics of the corresponding AP chip
 * environment and not the characteristics of the x86 processor.
 *
 * This chip environment represents one unique instance of such a chip pair.
 */
#if !XNU_KERNEL_PRIVATE
IMG4_API_AVAILABLE_20200508
OS_EXPORT
const img4_chip_t _img4_chip_ap_hybrid;
#define IMG4_CHIP_AP_HYBRID (&_img4_chip_ap_hybrid)
#else
#define IMG4_CHIP_AP_HYBRID (img4if->i4if_v7.chip_ap_hybrid)
#endif

/*!
 * @const IMG4_CHIP_AP_REDUCED
 * An Application Processor on an Apple ARM SoC operating in a reduced security
 * configuration.
 *
 * This chip cannot be uniquely identified.
 */
#if !XNU_KERNEL_PRIVATE
IMG4_API_AVAILABLE_20200508
OS_EXPORT
const img4_chip_t _img4_chip_ap_reduced;
#define IMG4_CHIP_AP_REDUCED (&_img4_chip_ap_reduced)
#else
#define IMG4_CHIP_AP_REDUCED (img4if->i4if_v7.chip_ap_reduced)
#endif

/*!
 * @const IMG4_CHIP_AP_PERMISSIVE
 * An Application Processor on an Apple ARM SoC operating entirely within the
 * user's authority.
 *
 * This chip's identity is rooted in a device-specific authority rather than one
 * maintained by Apple.
 */
#if !XNU_KERNEL_PRIVATE
IMG4_API_AVAILABLE_20200508
OS_EXPORT
const img4_chip_t _img4_chip_ap_permissive;
#define IMG4_CHIP_AP_PERMISSIVE (&_img4_chip_ap_permissive)
#else
#define IMG4_CHIP_AP_PERMISSIVE (img4if->i4if_v8.chip_ap_permissive)
#endif

/*!
 * @const IMG4_CHIP_AP_LOCAL_BLESSED
 * An Application Processor on an Apple ARM SoC which is executing payloads from
 * a future local policy that has not yet booted.
 */
#if !XNU_KERNEL_PRIVATE
IMG4_API_AVAILABLE_20220513
OS_EXPORT
const img4_chip_t _img4_chip_ap_local_blessed;
#define IMG4_CHIP_AP_LOCAL_BLESSED (&_img4_chip_ap_local_blessed)
#else
#define IMG4_CHIP_AP_LOCAL_BLESSED (img4if->i4if_v18.chip_ap_local_blessed)
#endif

/*!
 * @const IMG4_CHIP_AP_HYBRID_MEDIUM
 * An Intel x86 processor whose chain of trust is rooted in an instance of a
 * {@link IMG4_CHIP_AP_SHA2_384} chip and is operating in a "medium security"
 * mode due to a user-approved security degradation.
 *
 * This chip cannot be uniquely identified.
 */
#if !XNU_KERNEL_PRIVATE
IMG4_API_AVAILABLE_20200508
OS_EXPORT
const img4_chip_t _img4_chip_ap_hybrid_medium;
#define IMG4_CHIP_AP_HYBRID_MEDIUM (&_img4_chip_ap_hybrid_medium)
#else
#define IMG4_CHIP_AP_HYBRID_MEDIUM (img4if->i4if_v8.chip_ap_hybrid_medium)
#endif

/*!
 * @const IMG4_CHIP_AP_HYBRID_RELAXED
 * An Intel x86 processor whose chain of trust is rooted in an instance of a
 * {@link IMG4_CHIP_AP_SHA2_384} chip and is operating with no secure boot
 * due to a user-approved security degradation.
 *
 * This chip cannot be uniquely identified.
 */
#if !XNU_KERNEL_PRIVATE
IMG4_API_AVAILABLE_20200508
OS_EXPORT
const img4_chip_t _img4_chip_ap_hybrid_relaxed;
#define IMG4_CHIP_AP_HYBRID_RELAXED (&_img4_chip_ap_hybrid_relaxed)
#else
#define IMG4_CHIP_AP_HYBRID_RELAXED (img4if->i4if_v8.chip_ap_hybrid_relaxed)
#endif

/*!
 * @const IMG4_CHIP_AP_INTRANSIGENT
 * An Application Processor which is incapable of executing code. This chip
 * environment's root of trust is a certificate authority which has never and
 * will never issue any certificates.
 */
#if !XNU_KERNEL_PRIVATE
IMG4_API_AVAILABLE_20210113
OS_EXPORT
const img4_chip_t _img4_chip_ap_intransigent;
#define IMG4_CHIP_AP_INTRANSIGENT (&_img4_chip_ap_intransigent)
#else
#define IMG4_CHIP_AP_INTRANSIGENT (img4if->i4if_v11.chip_ap_intransigent)
#endif

/*!
 * @const IMG4_CHIP_AP_SUPPLEMENTAL
 * An Application Processor whose root of trust resides in the
 * {@link IMG4_RUNTIME_OBJECT_SPEC_SUPPLEMENTAL_ROOT} object. Once the
 * supplemental root object is executed on the host's AP, this chip environment
 * is available to execute payloads.
 */
#if !XNU_KERNEL_PRIVATE
IMG4_API_AVAILABLE_20210113
OS_EXPORT
const img4_chip_t _img4_chip_ap_supplemental;
#define IMG4_CHIP_AP_SUPPLEMENTAL (&_img4_chip_ap_supplemental)
#else
#define IMG4_CHIP_AP_SUPPLEMENTAL (img4if->i4if_v11.chip_ap_supplemental)
#endif

/*!
 * @const IMG4_CHIP_AP_VMA2
 * The Application Processor of a virtualized Apple ARM device.
 *
 * This chip environment represents one unique instance of such a chip on the
 * host device.
 */
#if !XNU_KERNEL_PRIVATE
IMG4_API_AVAILABLE_20210113
OS_EXPORT
const img4_chip_t _img4_chip_ap_vma2;
#define IMG4_CHIP_AP_VMA2 (&_img4_chip_ap_vma2)
#else
#define IMG4_CHIP_AP_VMA2 (img4if->i4if_v13.chip_ap_vma2)
#endif

/*!
 * @const IMG4_CHIP_AP_VMA2_CLONE
 * The Application Processor of a virtualized Apple ARM device which has been
 * cloned from another on the same host.
 *
 * This chip environment cannot be uniquely identified.
 */
#if !XNU_KERNEL_PRIVATE
IMG4_API_AVAILABLE_20210113
OS_EXPORT
const img4_chip_t _img4_chip_ap_vma2_clone;
#define IMG4_CHIP_AP_VMA2_CLONE (&_img4_chip_ap_vma2_clone)
#else
#define IMG4_CHIP_AP_VMA2_CLONE (img4if->i4if_v13.chip_ap_vma2_clone)
#endif

OS_ASSUME_NONNULL_END

#endif // __IMG4_CHIP_AP_H
STAGEEOF
    echo "Staged img4/chip_ap.h (no KDK)"
fi
if [ ! -f "EXTERNAL_HEADERS/img4/chip_ap_category.h" ]; then
    mkdir -p "EXTERNAL_HEADERS/img4"
    cat > "EXTERNAL_HEADERS/img4/chip_ap_category.h" <<'STAGEEOF'
/*!
 * @header
 * Categorized AP chip environments. These are now defunct.
 */
#ifndef __IMG4_CHIP_AP_CATEGORY_H
#define __IMG4_CHIP_AP_CATEGORY_H

#ifndef __IMG4_INDIRECT
#error "Please #include <img4/firmware.h> instead of this file directly"
#endif // __IMG4_INDIRECT

OS_ASSUME_NONNULL_BEGIN

/*!
 * @const IMG4_CHIP_AP_CATEGORY_FF02
 * The Application Processor on an Intel Mac product.
 *
 * This chip environment represents one unique instance of such a chip, though
 * the uniqueness is not enforced by a secure boot chain with anti-replay
 * properties, and therefore this chip environment should be considered as
 * equivalent to a global signing environment.
 */
#if !XNU_KERNEL_PRIVATE
IMG4_API_AVAILABLE_20210305
OS_EXPORT
const img4_chip_t _img4_chip_ap_category_ff02;
#define IMG4_CHIP_AP_CATEGORY_FF02 (&_img4_chip_ap_category_ff02)
#else
#define IMG4_CHIP_AP_CATEGORY_FF02 (img4if->i4if_v12.chip_ap_category_ff02)
#endif

/*!
 * @const IMG4_CHIP_AP_CATEGORY_FF03
 * An Intel x86 processor whose chain of trust is rooted in an instance of a
 * {@link IMG4_CHIP_AP_SHA2_384} chip.
 *
 * This chip environment represents one unique instance of such a chip pair.
 */
#if !XNU_KERNEL_PRIVATE
IMG4_API_AVAILABLE_20210305
OS_EXPORT
const img4_chip_t _img4_chip_ap_category_ff03;
#define IMG4_CHIP_AP_CATEGORY_FF03 (&_img4_chip_ap_category_ff03)
#else
#define IMG4_CHIP_AP_CATEGORY_FF03 (img4if->i4if_v12.chip_ap_category_ff03)
#endif

/*!
 * @const IMG4_CHIP_AP_CATEGORY_FF04_F0
 * The Application Processor of an Apple ARM SoC in an Apple Silicon Mac
 * product.
 *
 * This chip environment represents one unique instance of such a chip.
 */
#if !XNU_KERNEL_PRIVATE
IMG4_API_AVAILABLE_20210305
OS_EXPORT
const img4_chip_t _img4_chip_ap_category_ff04_f0;
#define IMG4_CHIP_AP_CATEGORY_FF04_F0 (&_img4_chip_ap_category_ff04_f0)
#else
#define IMG4_CHIP_AP_CATEGORY_FF04_F0 \
		(img4if->i4if_v12.chip_ap_category_ff04_f0)
#endif

/*!
 * @const IMG4_CHIP_AP_CATEGORY_FF04_F1
 * The Application Processor of an Apple ARM SoC in an iPhone, iPad, or iPod
 * touch product.
 *
 * This chip environment represents one unique instance of such a chip.
 */
#if !XNU_KERNEL_PRIVATE
IMG4_API_AVAILABLE_20210305
OS_EXPORT
const img4_chip_t _img4_chip_ap_category_ff04_f1;
#define IMG4_CHIP_AP_CATEGORY_FF04_F1 (&_img4_chip_ap_category_ff04_f1)
#else
#define IMG4_CHIP_AP_CATEGORY_FF04_F1 \
		(img4if->i4if_v12.chip_ap_category_ff04_f1)
#endif

/*!
 * @const IMG4_CHIP_AP_CATEGORY_FF04_F2
 * The Application Processor of an Apple ARM SoC in an watch product.
 *
 * This chip environment represents one unique instance of such a chip.
 */
#if !XNU_KERNEL_PRIVATE
IMG4_API_AVAILABLE_20210305
OS_EXPORT
const img4_chip_t _img4_chip_ap_category_ff04_f2;
#define IMG4_CHIP_AP_CATEGORY_FF04_F2 (&_img4_chip_ap_category_ff04_f2)
#else
#define IMG4_CHIP_AP_CATEGORY_FF04_F2 \
		(img4if->i4if_v12.chip_ap_category_ff04_f2)
#endif

/*!
 * @const IMG4_CHIP_AP_CATEGORY_FF04_F3
 * The Application Processor of an Apple ARM SoC in an tv or HomePod product.
 *
 * This chip environment represents one unique instance of such a chip.
 */
#if !XNU_KERNEL_PRIVATE
IMG4_API_AVAILABLE_20210305
OS_EXPORT
const img4_chip_t _img4_chip_ap_category_ff04_f3;
#define IMG4_CHIP_AP_CATEGORY_FF04_F3 (&_img4_chip_ap_category_ff04_f3)
#else
#define IMG4_CHIP_AP_CATEGORY_FF04_F3 \
		(img4if->i4if_v12.chip_ap_category_ff04_f3)
#endif

OS_ASSUME_NONNULL_END

#endif // __IMG4_CHIP_AP_CATEGORY_H
STAGEEOF
    echo "Staged img4/chip_ap_category.h (no KDK)"
fi
if [ ! -f "EXTERNAL_HEADERS/img4/chip_ap_software.h" ]; then
    mkdir -p "EXTERNAL_HEADERS/img4"
    cat > "EXTERNAL_HEADERS/img4/chip_ap_software.h" <<'STAGEEOF'
/*!
 * @header
 * Software AP chip environments.
 */
#ifndef __IMG4_CHIP_AP_SOFTWARE_H
#define __IMG4_CHIP_AP_SOFTWARE_H

#ifndef __IMG4_INDIRECT
#error "Please #include <img4/firmware.h> instead of this file directly"
#endif // __IMG4_INDIRECT

OS_ASSUME_NONNULL_BEGIN

/*!
 * @const IMG4_CHIP_AP_SOFTWARE_FF00
 * A software-defined chip environment whose firmwares are executed on any
 * Application Processor on an Apple ARM SoC. The firmwares are loadable trust
 * caches shipped with OTA update brains.
 *
 * This chip cannot be uniquely identified.
 */
#if !XNU_KERNEL_PRIVATE
IMG4_API_AVAILABLE_20200508
OS_EXPORT
const img4_chip_t _img4_chip_ap_software_ff00;
#define IMG4_CHIP_AP_SOFTWARE_FF00 (&_img4_chip_ap_software_ff00)
#else
#define IMG4_CHIP_AP_SOFTWARE_FF00 (img4if->i4if_v7.chip_ap_software_ff00)
#endif

/*!
 * @const IMG4_CHIP_AP_SOFTWARE_FF01
 * A software-defined chip environment whose firmwares are executed on any
 * Application Processor on an Apple ARM SoC. The firmwares are loadable trust
 * caches which are shipped in the Install Assistant and loaded by an
 * unprivileged trampoline.
 *
 * This chip cannot be uniquely identified.
 */
#if !XNU_KERNEL_PRIVATE
IMG4_API_AVAILABLE_20200508
OS_EXPORT
const img4_chip_t _img4_chip_ap_software_ff01;
#define IMG4_CHIP_AP_SOFTWARE_FF01 (&_img4_chip_ap_software_ff01)
#else
#define IMG4_CHIP_AP_SOFTWARE_FF01 (img4if->i4if_v7.chip_ap_software_ff01)
#endif

/*!
 * @const IMG4_CHIP_AP_SOFTWARE_FF06
 * A software-defined chip environment whose firmwares are executed on any
 * Application Processor on an Apple ARM SoC. The firmwares are loadable trust
 * caches which are shipped in the preboot volume.
 *
 * This chip cannot be uniquely identified.
 */
#if !XNU_KERNEL_PRIVATE
IMG4_API_AVAILABLE_20210113
OS_EXPORT
const img4_chip_t _img4_chip_ap_software_ff06;
#define IMG4_CHIP_AP_SOFTWARE_FF06 (&_img4_chip_ap_software_ff06)
#else
#define IMG4_CHIP_AP_SOFTWARE_FF06 (img4if->i4if_v11.chip_ap_software_ff06)
#endif

OS_ASSUME_NONNULL_END

#endif // __IMG4_CHIP_AP_SOFTWARE_H
STAGEEOF
    echo "Staged img4/chip_ap_software.h (no KDK)"
fi
if [ ! -f "EXTERNAL_HEADERS/img4/chip_cryptex1.h" ]; then
    mkdir -p "EXTERNAL_HEADERS/img4"
    cat > "EXTERNAL_HEADERS/img4/chip_cryptex1.h" <<'STAGEEOF'
/*!
 * @header
 * Cryptex1 chip environments.
 */
#ifndef __IMG4_CHIP_CRYPTEX1_H
#define __IMG4_CHIP_CRYPTEX1_H

#ifndef __IMG4_INDIRECT
#error "Please #include <img4/firmware.h> instead of this file directly"
#endif // __IMG4_INDIRECT

OS_ASSUME_NONNULL_BEGIN

/*!
 * @const IMG4_CHIP_CRYPTEX1_BOOT
 * A virtual coprocessor environment hosted on the AP which derives its unique
 * identity from the hosting AP. This chip assists in booting the AP's
 * userspace.
 */
#if !XNU_KERNEL_PRIVATE
IMG4_API_AVAILABLE_20211126
OS_EXPORT
const img4_chip_t _img4_chip_cryptex1_boot;
#define IMG4_CHIP_CRYPTEX1_BOOT (&_img4_chip_cryptex1_boot)
#else
#define IMG4_CHIP_CRYPTEX1_BOOT (img4if->i4if_v17.chip_cryptex1_boot)
#endif

/*!
 * @const IMG4_CHIP_CRYPTEX1_BOOT_REDUCED
 * A virtual coprocessor environment hosted on the reduced-security AP which
 * derives its unique identity from the hosting AP. This chip assists in booting
 * the AP's userspace.
 */
#if !XNU_KERNEL_PRIVATE
IMG4_API_AVAILABLE_20211126
OS_EXPORT
const img4_chip_t _img4_chip_cryptex1_boot_reduced;
#define IMG4_CHIP_CRYPTEX1_BOOT_REDUCED \
		(&_img4_chip_cryptex1_boot_reduced)
#else
#define IMG4_CHIP_CRYPTEX1_BOOT_REDUCED \
		(img4if->i4if_v17.chip_cryptex1_boot_reduced)
#endif

/*!
 * @const IMG4_CHIP_CRYPTEX1_BOOT_PROPOSAL
 * Equivalent to {@link IMG4_CHIP_CRYPTEX1_BOOT} with internal use constraints
 * relaxed to permit verification in scenarios where the currently-booted AP may
 * not represent the ultimate execution environment.
 *
 * @discussion
 * This environment should not be used for payload execution on the AP and is
 * intended to facilitate local policy signing in the SEP.
 */
#if !XNU_KERNEL_PRIVATE
IMG4_API_AVAILABLE_20220401
OS_EXPORT
const img4_chip_t _img4_chip_cryptex1_boot_proposal;
#define IMG4_CHIP_CRYPTEX1_BOOT_PROPOSAL (&_img4_chip_cryptex1_boot_proposal)
#else
#define IMG4_CHIP_CRYPTEX1_BOOT_PROPOSAL \
		(img4if->i4if_v18.chip_cryptex1_boot_proposal)
#endif

/*!
 * @const IMG4_CHIP_CRYPTEX1_BOOT_REDUCED_PROPOSAL
 * Equivalent to {@link IMG4_CHIP_CRYPTEX1_BOOT_REDUCED} with internal use
 * constraints relaxed to permit verification in scenarios where the currently-
 * booted AP may not represent the ultimate execution environment.
 *
 * @discussion
 * This environment should not be used for payload execution on the AP and is
 * intended to facilitate local policy signing in the SEP.
 */
#if !XNU_KERNEL_PRIVATE
IMG4_API_AVAILABLE_20220401
OS_EXPORT
const img4_chip_t _img4_chip_cryptex1_boot_reduced_proposal;
#define IMG4_CHIP_CRYPTEX1_BOOT_REDUCED_PROPOSAL \
		(&_img4_chip_cryptex1_boot_reduced_proposal)
#else
#define IMG4_CHIP_CRYPTEX1_BOOT_REDUCED_PROPOSAL \
		(img4if->i4if_v18.chip_cryptex1_boot_reduced_proposal)
#endif

/*!
 * @const IMG4_CHIP_CRYPTEX1_BOOT_X86
 * A virtual coprocessor environment hosted on an x86 chip which has no unique
 * identity. This chip assists in booting the x86 processor's userspace.
 */
#if !XNU_KERNEL_PRIVATE
IMG4_API_AVAILABLE_20211126
OS_EXPORT
const img4_chip_t _img4_chip_cryptex1_boot_x86;
#define IMG4_CHIP_CRYPTEX1_BOOT_X86 (&_img4_chip_cryptex1_boot_x86)
#else
#define IMG4_CHIP_CRYPTEX1_BOOT_X86 (img4if->i4if_v17.chip_cryptex1_boot_x86)
#endif

/*!
 * @const IMG4_CHIP_CRYPTEX1_BOOT_VMA2
 * A virtual coprocessor environment hosted on a virtualized ARM AP which
 * derives its unique identity from the hosting AP. This chip assists in booting
 * the AP's userspace.
 */
#if !XNU_KERNEL_PRIVATE
IMG4_API_AVAILABLE_20220128
OS_EXPORT
const img4_chip_t _img4_chip_cryptex1_boot_vma2;
#define IMG4_CHIP_CRYPTEX1_BOOT_VMA2 (&_img4_chip_cryptex1_boot_vma2)
#else
#define IMG4_CHIP_CRYPTEX1_BOOT_VMA2 (img4if->i4if_v17.chip_cryptex1_boot_vma2)
#endif

/*!
 * @const IMG4_CHIP_CRYPTEX1_BOOT_VMA2_CLONE
 * A virtual coprocessor environment hosted on a virtualized ARM AP which
 * derives its unique identity from the hosting AP. This chip assists in booting
 * the AP's userspace. This is the clone version which doesn't enforce ECID
 * and UDID.
 */
#if !XNU_KERNEL_PRIVATE
IMG4_API_AVAILABLE_20220322
OS_EXPORT
const img4_chip_t _img4_chip_cryptex1_boot_vma2_clone;
#define IMG4_CHIP_CRYPTEX1_BOOT_VMA2_CLONE \
		(&_img4_chip_cryptex1_boot_vma2_clone)
#else
#define IMG4_CHIP_CRYPTEX1_BOOT_VMA2_CLONE \
		(img4if->i4if_v18.chip_cryptex1_boot_vma2_clone)
#endif

/*!
 * @const IMG4_CHIP_CRYPTEX1_BOOT_VMA2_PROPOSAL
 * Equivalent to {@link IMG4_CHIP_CRYPTEX1_BOOT_VMA2} with internal use
 * constraints relaxed to permit verification in scenarios where the currently-
 * booted AP may not represent the ultimate execution environment.
 *
 * @discussion
 * This environment should not be used for payload execution on the AP and is
 * intended to facilitate local policy signing in the BootPolicy kext.
 */
#if !XNU_KERNEL_PRIVATE
IMG4_API_AVAILABLE_20220401
OS_EXPORT
const img4_chip_t _img4_chip_cryptex1_boot_vma2_proposal;
#define IMG4_CHIP_CRYPTEX1_BOOT_VMA2_PROPOSAL \
		(&_img4_chip_cryptex1_boot_vma2_proposal)
#else
#define IMG4_CHIP_CRYPTEX1_BOOT_VMA2_PROPOSAL \
		(img4if->i4if_v18.chip_cryptex1_boot_vma2_proposal)
#endif

/*!
 * @const IMG4_CHIP_CRYPTEX1_BOOT_VMA2_CLONE_PROPOSAL
 * Equivalent to {@link IMG4_CHIP_CRYPTEX1_BOOT_VMA2_CLONE} with internal use
 * constraints relaxed to permit verification in scenarios where the currently-
 * booted AP may not represent the ultimate execution environment.
 *
 * @discussion
 * This environment should not be used for payload execution on the AP and is
 * intended to facilitate local policy signing in the BootPolicy kext.
 */
#if !XNU_KERNEL_PRIVATE
IMG4_API_AVAILABLE_20220401
OS_EXPORT
const img4_chip_t _img4_chip_cryptex1_boot_vma2_clone_proposal;
#define IMG4_CHIP_CRYPTEX1_BOOT_VMA2_CLONE_PROPOSAL \
		(&_img4_chip_cryptex1_boot_vma2_clone_proposal)
#else
#define IMG4_CHIP_CRYPTEX1_BOOT_VMA2_CLONE_PROPOSAL \
		(img4if->i4if_v18.chip_cryptex1_boot_vma2_clone_proposal)
#endif

/*!
 * @const IMG4_CHIP_CRYPTEX1_PREBOOT
 * A virtual coprocessor environment hosted on the AP which derives its unique
 * identity from the hosting AP. This chip permits executing payloads intended
 * for the next boot prior to that boot. It does not assist in booting the AP.
 */
#if !XNU_KERNEL_PRIVATE
IMG4_API_AVAILABLE_20211126
OS_EXPORT
const img4_chip_t _img4_chip_cryptex1_preboot;
#define IMG4_CHIP_CRYPTEX1_PREBOOT (&_img4_chip_cryptex1_preboot)
#else
#define IMG4_CHIP_CRYPTEX1_PREBOOT (img4if->i4if_v17.chip_cryptex1_preboot)
#endif

/*!
 * @const IMG4_CHIP_CRYPTEX1_PREBOOT_REDUCED
 * A virtual coprocessor environment hosted on the reduced-security AP which
 * derives its unique identity from the hosting AP. This chip permits executing
 * payloads intended for the next boot prior to that boot. It does not assist in
 * booting the AP.
 */
#if !XNU_KERNEL_PRIVATE
IMG4_API_AVAILABLE_20211126
OS_EXPORT
const img4_chip_t _img4_chip_cryptex1_preboot_reduced;
#define IMG4_CHIP_CRYPTEX1_PREBOOT_REDUCED \
		(&_img4_chip_cryptex1_preboot_reduced)
#else
#define IMG4_CHIP_CRYPTEX1_PREBOOT_REDUCED \
		(img4if->i4if_v17.chip_cryptex1_preboot_reduced)
#endif

/*!
 * @const IMG4_CHIP_CRYPTEX1_PREBOOT_X86
 * A virtual coprocessor environment hosted on an x86 chip which has no unique
 * identity. This chip permits executing payloads intended for the next boot
 * prior to that boot. It does not assist in booting the x86 chip.
 */
#if !XNU_KERNEL_PRIVATE
IMG4_API_AVAILABLE_20211126
OS_EXPORT
const img4_chip_t _img4_chip_cryptex1_preboot_x86;
#define IMG4_CHIP_CRYPTEX1_PREBOOT_X86 \
		(&_img4_chip_cryptex1_preboot_x86)
#else
#define IMG4_CHIP_CRYPTEX1_PREBOOT_X86 \
		(img4if->i4if_v17.chip_cryptex1_preboot_x86)
#endif

/*!
 * @const IMG4_CHIP_CRYPTEX1_PREBOOT_VMA2
 * A virtual coprocessor environment hosted on a virtualized ARM AP which
 * derives its unique identity from the hosting AP. This chip permits executing
 * payloads intended for the next boot prior to that boot. It does not assist in
 * booting the AP.
 */
#if !XNU_KERNEL_PRIVATE
IMG4_API_AVAILABLE_20220128
OS_EXPORT
const img4_chip_t _img4_chip_cryptex1_preboot_vma2;
#define IMG4_CHIP_CRYPTEX1_PREBOOT_VMA2 \
		(&_img4_chip_cryptex1_preboot_vma2)
#else
#define IMG4_CHIP_CRYPTEX1_PREBOOT_VMA2 \
		(img4if->i4if_v17.chip_cryptex1_preboot_vma2)
#endif

/*!
 * @const IMG4_CHIP_CRYPTEX1_PREBOOT_VMA2_CLONE
 * A virtual coprocessor environment hosted on a virtualized ARM AP which
 * derives its unique identity from the hosting AP. This chip permits executing
 * payloads intended for the next boot prior to that boot. It does not assist in
 * booting the AP. This is the clone version which doesn't enforce ECID
 * and UDID.
 */
#if !XNU_KERNEL_PRIVATE
IMG4_API_AVAILABLE_20220322
OS_EXPORT
const img4_chip_t _img4_chip_cryptex1_preboot_vma2_clone;
#define IMG4_CHIP_CRYPTEX1_PREBOOT_VMA2_CLONE \
		(&_img4_chip_cryptex1_preboot_vma2_clone)
#else
#define IMG4_CHIP_CRYPTEX1_PREBOOT_VMA2_CLONE \
		(img4if->i4if_v18.chip_cryptex1_preboot_vma2_clone)
#endif

/*!
 * @const IMG4_CHIP_CRYPTEX1_ASSET
 * A virtual coprocessor environment hosted on the AP which derives its unique
 * identity from the hosting AP. This chip assists in executing MobileAsset
 * brain payloads during runtime, after the host AP has booted its userspace.
 */
#if !XNU_KERNEL_PRIVATE
IMG4_API_AVAILABLE_20211126
OS_EXPORT
const img4_chip_t _img4_chip_cryptex1_asset;
#define IMG4_CHIP_CRYPTEX1_ASSET (&_img4_chip_cryptex1_asset)
#else
#define IMG4_CHIP_CRYPTEX1_ASSET (img4if->i4if_v17.chip_cryptex1_asset)
#endif

/*!
 * @const IMG4_CHIP_CRYPTEX1_ASSET_X86
 * A virtual coprocessor environment hosted on the AP which derives its unique
 * identity from the hosting AP. This chip assists in executing MobileAsset
 * brain payloads during runtime, after the host AP has booted its userspace.
 */
#if !XNU_KERNEL_PRIVATE
IMG4_API_AVAILABLE_20220401
OS_EXPORT
const img4_chip_t _img4_chip_cryptex1_asset_x86;
#define IMG4_CHIP_CRYPTEX1_ASSET_X86 (&_img4_chip_cryptex1_asset_x86)
#else
#define IMG4_CHIP_CRYPTEX1_ASSET_X86 (img4if->i4if_v18.chip_cryptex1_asset_x86)
#endif

OS_ASSUME_NONNULL_END

#endif // __IMG4_CHIP_CRYPTEX1_H
STAGEEOF
    echo "Staged img4/chip_cryptex1.h (no KDK)"
fi
if [ ! -f "EXTERNAL_HEADERS/img4/chip_sep.h" ]; then
    mkdir -p "EXTERNAL_HEADERS/img4"
    cat > "EXTERNAL_HEADERS/img4/chip_sep.h" <<'STAGEEOF'
/*!
 * @header
 * Cryptex1 chip environments.
 */
#ifndef __IMG4_CHIP_SEP_H
#define __IMG4_CHIP_SEP_H

#ifndef __IMG4_INDIRECT
#error "Please #include <img4/firmware.h> instead of this file directly"
#endif // __IMG4_INDIRECT

OS_ASSUME_NONNULL_BEGIN

/*!
 * @const IMG4_CHIP_SEP_SHA1
 * The Secure Enclave Processor on an Apple ARM SoC with an embedded sha1
 * certifcate chain.
 *
 * This chip environment represents one unique instance of such a chip.
 */
#if !XNU_KERNEL_PRIVATE
IMG4_API_AVAILABLE_20211119
OS_EXPORT
const img4_chip_t _img4_chip_sep_sha1;
#define IMG4_CHIP_SEP_SHA1 (&_img4_chip_sep_sha1)
#else
#define IMG4_CHIP_SEP_SHA1 (img4if->i4if_v16.chip_sep_sha1)
#endif

/*!
 * @const IMG4_CHIP_SEP_SHA2_384
 * The Secure Enclave Processor on an Apple ARM SoC with an embedded sha2-384
 * certifcate chain.
 *
 * This chip environment represents one unique instance of such a chip.
 */
#if !XNU_KERNEL_PRIVATE
IMG4_API_AVAILABLE_20211119
OS_EXPORT
const img4_chip_t _img4_chip_sep_sha2_384;
#define IMG4_CHIP_SEP_SHA2_384 (&_img4_chip_sep_sha2_384)
#else
#define IMG4_CHIP_SEP_SHA2_384 (img4if->i4if_v16.chip_sep_sha2_384)
#endif

OS_ASSUME_NONNULL_END

#endif // __IMG4_CHIP_SEP_H
STAGEEOF
    echo "Staged img4/chip_sep.h (no KDK)"
fi
if [ ! -f "EXTERNAL_HEADERS/img4/chip_x86.h" ]; then
    mkdir -p "EXTERNAL_HEADERS/img4"
    cat > "EXTERNAL_HEADERS/img4/chip_x86.h" <<'STAGEEOF'
/*!
 * @header
 * x86 chip environments.
 */
#ifndef __IMG4_CHIP_X86_H
#define __IMG4_CHIP_X86_H

#ifndef __IMG4_INDIRECT
#error "Please #include <img4/firmware.h> instead of this file directly"
#endif // __IMG4_INDIRECT

OS_ASSUME_NONNULL_BEGIN

/*!
 * @const IMG4_CHIP_X86
 * An Intel x86 processor which cannot be uniquely identified.
 */
#if !XNU_KERNEL_PRIVATE
IMG4_API_AVAILABLE_20200508
OS_EXPORT
const img4_chip_t _img4_chip_x86;
#define IMG4_CHIP_X86 (&_img4_chip_x86)
#else
#define IMG4_CHIP_X86 (img4if->i4if_v7.chip_x86)
#endif

/*!
 * @const IMG4_CHIP_X86_SOFTWARE_8012
 * A software-defined chip environment describing a virtualized x86 processor.
 * Since the virtual machine is at the mercy of the VM, support for any sort of
 * chip identity may not be available. Therefore this environment is returned
 * from {@link img4_chip_select_personalized_ap} and
 * {@link img4_chip_select_effective_ap} when it is called on a virtual machine
 * so that the appropriate chip environment is present entirely in software.
 *
 * This environment provides an equivalent software identity to that of
 * the {@link IMG4_CHIP_X86} chip environment on non-Gibraltar Macs.
 *
 * @discussion
 * Do not use this environment directly.
 */
#if !XNU_KERNEL_PRIVATE
IMG4_API_AVAILABLE_20200508
OS_EXPORT
const img4_chip_t _img4_chip_x86_software_8012;
#define IMG4_CHIP_X86_SOFTWARE_8012 (&_img4_chip_x86_software_8012)
#else
#define IMG4_CHIP_X86_SOFTWARE_8012 (img4if->i4if_v7.chip_x86_software_8012)
#endif

OS_ASSUME_NONNULL_END

#endif // __IMG4_CHIP_X86_H
STAGEEOF
    echo "Staged img4/chip_x86.h (no KDK)"
fi
if [ ! -f "EXTERNAL_HEADERS/img4/firmware.h" ]; then
    mkdir -p "EXTERNAL_HEADERS/img4"
    cat > "EXTERNAL_HEADERS/img4/firmware.h" <<'STAGEEOF'
/*!
 * @header
 * Interfaces for manipulating Image4 firmware objects.
 */
#ifndef __IMG4_FIRMWARE_H
#define __IMG4_FIRMWARE_H

#define __IMG4_INDIRECT 1
#include <img4/api.h>

/*!
 * @discussion
 * When used from the pmap layer, this header pulls in the types from libsa,
 * which conflict with the BSD sys/types.h header that we need to pull in. But
 * we only need it for the errno_t typedef and the vnode_t typedef. So when
 * building MACH_KERNEL_PRIVATE, we do two things:
 *
 *     1. Explicitly pull in <sys/_types/_errno_t.h>, so we get errno_t and
 *        nothing else (no transitive #include's)
 *     2. #define _SYS_TYPES_H_ before #includ'ing <sys/kernel_types.h> so that
 *        we don't get the transitive #include of <sys/types.h> but we still get
 *        the definitions we need
 */
#if IMG4_TARGET_XNU
#if MACH_KERNEL_PRIVATE
#define _SYS_TYPES_H_ 1
#include <sys/kernel_types.h>
#include <sys/_types/_errno_t.h>
#else
#include <sys/kernel_types.h>
#include <sys/types.h>
#endif

#if XNU_KERNEL_PRIVATE
#include <img4/4xnu.h>
#endif
#endif // IMG4_TARGET_XNU

#if IMG4_TARGET_DARWIN
#include <os/stdio.h>
#include <sys/types.h>
#include <img4/4ignition.h>
#include <img4/4MSU.h>
#endif

__BEGIN_DECLS
OS_ASSUME_NONNULL_BEGIN

/*!
 * @typedef img4_4cc_t
 * A type which represents a four-character code (4cc) that identifies the
 * firmware. These 4cc's are statically assigned and correspond to long-form tag
 * names -- e.g. the 4cc 'krnl' corresponds to the "KernelCache" tag.
 */
IMG4_API_AVAILABLE_20200508
typedef uint32_t img4_4cc_t;

/*!
 * @typedef img4_buff_t
 * A structure describing a buffer. See {@link _img4_buff}.
 */
IMG4_API_AVAILABLE_20200508
typedef struct _img4_buff img4_buff_t;

/*!
 * @const IMG4_DGST_STRUCT_VERSION
 * The version of the {@link img4_dgst_t} structure supported by the
 * implementation.
 */
#define IMG4_DGST_STRUCT_VERSION (0u)

/*!
 * @const IMG4_DGST_MAX_LEN
 * The maximum length of a digest representable by an {@link img4_dgst_t}.
 */
#define IMG4_DGST_MAX_LEN (48u)

/*!
 * @typedef img4_dgst_t
 * A type representing an Image4 identifier which is a digest.
 *
 * @field i4d_len
 * The version of the structure. Initialize to {@link IMG4_DGST_STRUCT_VERSION}.
 *
 * @field i4d_len
 * The length of the digest.
 *
 * @field i4d_bytes
 * The digest bytes.
 */
IMG4_API_AVAILABLE_20200508
typedef struct _img4_dgst {
	img4_struct_version_t i4d_version;
	size_t i4d_len;
	uint8_t i4d_bytes[IMG4_DGST_MAX_LEN];
} img4_dgst_t;

/*!
 * @const IMG4_DGST_INIT
 * A convenience initializer for an {@link img4_dgst_t} structure.
 */
#if defined(__STDC_VERSION__) && __STDC_VERSION__ >= 199901L
#define IMG4_DGST_INIT (img4_dgst_t){ \
	.i4d_version = IMG4_DGST_STRUCT_VERSION, \
	.i4d_len = 0, \
	.i4d_bytes = {0}, \
}
#elif defined(__cplusplus) && __cplusplus >= 201103L
#define IMG4_DGST_INIT (img4_dgst_t{ \
	IMG4_DGST_STRUCT_VERSION, \
	0, \
	{0}, \
})
#elif defined(__cplusplus)
#define IMG4_DGST_INIT (img4_nonce_t((img4_nonce_t){ \
	IMG4_DGST_STRUCT_VERSION, \
	0, \
	{0}, \
}))
#else
#define IMG4_DGST_INIT {IMG4_DGST_STRUCT_VERSION}
#endif

/*!
 * @struct _img4_cstr
 * A type representing an Image4 identifier which is a C-string. These
 * identifiers can be no more than 64 bytes in length, including the null
 * terminating byte.
 *
 * @field i4b_len
 * The length of the C-string, not including the null terminating byte.
 *
 * @field i4b_cstr
 * The null-terminated C-string.
 *
 * @discussion
 * This structure is intentionally unversioned. It should never evolve into
 * anything more complex than it is.
 */
IMG4_API_AVAILABLE_20210113
typedef struct _img4_cstr {
	size_t i4cs_len;
	char i4cs_cstr[64];
} img4_cstr_t;

/*!
 * @const IMG4_CSTR_INIT
 * A convenience initializer for an {@link img4_cstr_t}.
 */
#if defined(__STDC_VERSION__) && __STDC_VERSION__ >= 199901L
#define IMG4_CSTR_INIT (img4_cstr_t){ \
	.i4cs_len = 0, \
	.i4cs_cstr = {0}, \
}
#elif defined(__cplusplus) && __cplusplus >= 201103L
#define IMG4_CSTR_INIT (img4_cstr_t{ \
	0, \
	{0}, \
})
#elif defined(__cplusplus)
#define IMG4_CSTR_INIT \
		(img4_cstr_t((img4_cstr_t){ \
	0, \
	{0}, \
}))
#else
#define IMG4_CSTR_INIT {0}
#endif

/*!
 * @typedef img4_chip_t
 * An opaque type describing a destination chip environment for the firmware
 * image.
 */
IMG4_API_AVAILABLE_20200508
typedef struct _img4_chip img4_chip_t;

/*!
 * @typedef img4_firmware_t
 * An opaque type describing an Image4 firmware object.
 */
IMG4_API_AVAILABLE_20200508
typedef struct _img4_firmware *img4_firmware_t;

/*!
 * @typedef img4_image_t
 * An opaque type describing an authenticated Image4 firmware image.
 */
IMG4_API_AVAILABLE_20200508
typedef struct _img4_image *img4_image_t;

/*!
 * @typedef img4_runtime_t
 * A structure describing required primitives in the operating environment's
 * runtime. See {@link _img4_runtime}.
 */
IMG4_API_AVAILABLE_20200508
typedef struct _img4_runtime img4_runtime_t;

OS_ASSUME_NONNULL_END

#include <img4/nonce.h>
#include <img4/object.h>
#include <img4/chip.h>
#include <img4/chip_ap.h>
#include <img4/chip_ap_category.h>
#include <img4/chip_ap_software.h>
#include <img4/chip_cryptex1.h>
#include <img4/chip_sep.h>
#include <img4/chip_x86.h>
#include <img4/image.h>
#include <img4/runtime.h>

OS_ASSUME_NONNULL_BEGIN

/*!
 * @typedef img4_firmware_authenticated_execute_t
 * A firmware execution function. This function is called when the firmware has
 * been successfully authenticated and is ready for execution.
 *
 * @param fw
 * The firmware which has been authenticated.
 *
 * @param image
 * The resulting firmware image that may be executed. The implementation will
 * pass NULL if there was a failure.
 *
 * This object is automatically freed by the implementation upon return.
 *
 * @param error
 * An error code describing the result of the authentication. If authentication
 * was successful, the implementation will pass zero. Otherwise, one of the
 * following error codes will be provided:
 *
 *     [EILSEQ]     The firmware data is not valid Image4 data -- this will not
 *                  be passed for firmwares created with
 *                  {@link IMG4_FIRMWARE_FLAG_BARE}
 *     [EFTYPE]     The attached manifest is not a valid Image4 manifest
 *     [ENOENT]     The attached manifest does not authenticate this type of
 *                  firmware
 *     [EAUTH]      The attached manifest is not authentic (i.e. was not signed
 *                  by an Apple CA)
 *     [EACCES]     The given chip does not satisfy the constraints of the
 *                  attached manifest
 *     [ESTALE]     The manifest has been invalidated and is no longer valid for
 *                  the provided chip
 *     [ENOEXEC]    The firmware has been corrupted, or the given chip does not
 *                  satisfy the constraints of the corresponding object in the
 *                  attached manifest
 *
 * @param _ctx
 * The user-provided context pointer.
 */
IMG4_API_AVAILABLE_20200508
typedef void (*img4_firmware_authenticated_execute_t)(
	const img4_firmware_t fw,
	img4_image_t _Nullable image,
	errno_t error,
	void *_ctx
);

#if IMG4_TARGET_EFI
typedef void (*img4_firmware_authenticated_execute_efi_t)(
	const img4_firmware_t fw,
	img4_image_t _Nullable image,
	EFI_STATUS status,
	void *_ctx
);
#endif

/*!
 * @define IMG4_FIRMWARE_EXECUTION_CONTEXT_STRUCT_VERSION
 * The version of the {@link img4_firmware_execution_context_t} structure
 * supported by the implementation.
 */
#define IMG4_FIRMWARE_EXECUTION_CONTEXT_STRUCT_VERSION (1u)

/*!
 * @typedef img4_firmware_execution_context_t
 * A structure describing the context in which a firmware is to be executed.
 *
 * @field i4fex_version
 * The version of the structure supported by the implementation. Initialize to
 * {@link IMG4_FIRMWARE_EXECUTION_CONTEXT_STRUCT_VERSION}.
 *
 * @field i4fex_execute
 * A pointer to the firmware execution function.
 *
 * @field i4fex_execute_efi
 * A pointer to the EFI-specific firmware execution function. This is only
 * available in the EFI environment. If both this field and
 * {@link i4fex_execute} are specified in the execution context, the
 * one which is called by the implementation will be undefined.
 *
 * This field was added in version 1 of the structure. It was not appended to
 * the end of the structure since the non-EFI structure did not change, and the
 * structure did not previously exist in the EFI environment. The version
 * increment was not strictly necessary, but was done for hygienic reasons.
 *
 * @field i4fex_context
 * A caller-provided context pointer that will be passed to functions invoked
 * from the execution context.
 */
IMG4_API_AVAILABLE_20200508
typedef struct _img4_firmware_execution_context {
	img4_struct_version_t i4fex_version;
	img4_firmware_authenticated_execute_t i4fex_execute;
#if IMG4_TARGET_EFI
	img4_firmware_authenticated_execute_efi_t i4fex_execute_efi;
#endif
	void *i4fex_context;
} img4_firmware_execution_context_t;

/*!
 * @typedef img4_firmware_flags_t
 * A bitfield modifying the behavior of an {@link img4_firmware_t} object.
 *
 * @const IMG4_FIRMWARE_FLAG_INIT
 * No bits set. This value is suitable for initialization purposes.
 *
 * @const IMG4_FIRMWARE_FLAG_ATTACHED_MANIFEST
 * The manifest authenticating the firmware is attached (i.e. the buffer given
 * represents a .img4 file).
 *
 * @const IMG4_FIRMWARE_FLAG_BARE
 * The firmware image is not wrapped with an Image4 payload structure. This flag
 * is mutually exclusive with {@link IMG4_FIRMWARE_FLAG_ATTACHED_MANIFEST}, and
 * if both are present, the implementation's behavior is undefined.
 *
 * @const IMG4_FIRMWARE_FLAG_SUBSEQUENT_STAGE
 * The firmware image extends an existing chain of trust. If set, the
 * runtime must provide a {@link i4rt_get_digest} function which returns a
 * digest for {@link IMG4_IDENTIFIER_CHMH}.
 *
 * If set, the firmware may optionally provide a {@link i4rt_get_bool} function
 * which returns a value for {@link IMG4_IDENTIFIER_AMNM}.
 *
 * @const IMG4_FIRMWARE_FLAG_RESPECT_AMNM
 * Forces the implementation to respect the manifest's AMNM entitlement if it is
 * present, even if the validation is creating a new chain of trust. This is
 * technically maybe sort of against the Image4 spec, but it is useful for
 * certain internal workflows (cf. v2.3, §2.2.10).
 *
 * This flag has no effect if {@link IMG4_FIRMWARE_FLAG_SUBSEQUENT_STAGE} is
 * also passed.
 *
 * @const IMG4_FIRMWARE_FLAG_PASSTHROUGH
 * Causes the wrapped payload bytes to be delivered to the image execution
 * callback. These bytes do not have the Image4 wrapping stripped.
 *
 * @const IMG4_FIRMWARE_FLAG_FORCE_ANTI_REPLAY
 * Force anti-replay enforcement even when performing just manifest evaluation
 * without executing a firmware. When executing a firmware, this flag need not
 * be passed in since anti-replay enforcement is always enabled.
 */
IMG4_API_AVAILABLE_20200508
OS_CLOSED_OPTIONS(img4_firmware_flags, uint64_t,
	IMG4_FIRMWARE_FLAG_INIT,
	IMG4_FIRMWARE_FLAG_ATTACHED_MANIFEST = (1 << 0),
	IMG4_FIRMWARE_FLAG_BARE = (1 << 1),
	IMG4_FIRMWARE_FLAG_SUBSEQUENT_STAGE = (1 << 2),
	IMG4_FIRMWARE_FLAG_RESPECT_AMNM = (1 << 3),
	IMG4_FIRMWARE_FLAG_PASSTHROUGH = (1 << 4),
	IMG4_FIRMWARE_FLAG_FORCE_ANTI_REPLAY = (1 << 5),
);

/*!
 * @function img4_firmware_new
 * Allocate and initialize a new firmware object.
 *
 * @param rt
 * The runtime in which to initialize the object.
 *
 * @param _4cc
 * The 4cc which distinguishes the firmware.
 *
 * @param buff
 * A buffer containing a valid Image4 payload (usually the contents of either a
 * .im4p or .img4 file).
 *
 * Upon return, the destructor in the buffer is replaced with NULL, and the
 * implementation assumes responsibility for deallocating the underlying memory.
 *
 * @param flags
 * Flags modifying the behavior of the object.
 *
 * @result
 * A new firmware object or NULL if there was an allocation failure. If
 * {@link rt} has a NULL allocation function, NULL is returned.
 *
 * @discussion
 * The resulting object assumes ownership of the given buffer.
 *
 * In the Darwin userspace runtime, NULL will not be returned.
 */
#if !XNU_KERNEL_PRIVATE
IMG4_API_AVAILABLE_20200508
OS_EXPORT OS_WARN_RESULT OS_MALLOC OS_NONNULL1 OS_NONNULL2 OS_NONNULL4
img4_firmware_t _Nullable
img4_firmware_new(const img4_runtime_t *rt,
		const img4_firmware_execution_context_t *exec,
		img4_4cc_t _4cc,
		img4_buff_t *buff,
		img4_firmware_flags_t flags);
#else
#define img4_firmware_new(...) (img4if->i4if_v7.firmware_new(__VA_ARGS__))
#endif

/*!
 * @function img4_firmware_new_from_vnode_4xnu
 * Allocate and initialize a new firmware object from a vnode.
 *
 * @param rt
 * The runtime in which to initialize the object. This interface is only
 * supported with the Darwin kernel runtime. If any other runtime is provided,
 * the implementation's behavior is undefined.
 *
 * @param _4cc
 * The 4cc which distinguishes the firmware.
 *
 * @param vn
 * A vnode representing a valid Image4 payload (usually the contents of either a
 * .im4p or .img4 file).
 *
 * @param flags
 * Flags modifying the behavior of the object.
 *
 * @result
 * A new firmware object or NULL if there was an allocation failure.
 *
 * @discussion
 * Verification of a vnode is performed by reading in chunks of data, updating
 * an ongoing hash operation with that data, and then discarding it. Therefore,
 * firmware objects created in this manner can only guarantee their validity at
 * the time the check was performed since the vnode's contents are not kept in
 * memory and may be tampered with after validation has been performed.
 *
 * As such, on successful execution, the image passed to the
 * {@link img4_firmware_authenticated_execute_t} function of the execution
 * context is NULL.
 *
 * Firmwares created with this interface cannot be created with the
 * {@link IMG4_FIRMWARE_FLAG_ATTACHED_MANIFEST} flag.
 */
#if IMG4_TARGET_XNU
#if !XNU_KERNEL_PRIVATE
IMG4_API_AVAILABLE_20200508
OS_EXPORT OS_WARN_RESULT OS_MALLOC OS_NONNULL1 OS_NONNULL2 OS_NONNULL4
img4_firmware_t _Nullable
img4_firmware_new_from_vnode_4xnu(const img4_runtime_t *rt,
		const img4_firmware_execution_context_t *exec,
		img4_4cc_t _4cc,
		vnode_t vn,
		img4_firmware_flags_t flags);
#else
#define img4_firmware_new_from_vnode_4xnu(...) \
		(img4if->i4if_v7.firmware_new_from_vnode_4xnu(__VA_ARGS__))
#endif // !XNU_KERNEL_PRIVATE
#endif // IMG4_TARGET_XNU

/*!
 * @function img4_firmware_new_from_fd_4MSM
 * Allocate and initialize a new firmware object from a file descriptor.
 *
 * @param rt
 * The runtime in which to initialize the object. This interface is only
 * supported with the Darwin userspace runtime. If any other runtime is
 * provided, the implementation's behavior is undefined.
 *
 * @param _4cc
 * The 4cc which distinguishes the firmware.
 *
 * @param fd
 * A pointer to a file descriptor representing a valid Image4 payload (usually
 * the contents of either a .im4p or .img4 file). The object assumes ownership
 * of the descriptor, and upon return, the value referenced by the pointer will
 * be set to -1.
 *
 * @param flags
 * Flags modifying the behavior of the object.
 *
 * @result
 * A new firmware object. The implementation will not return NULL.
 *
 * @discussion
 * This interface is the userspace equivalent of
 * {@link img4_firmware_new_from_vnode_4xnu}, and all the same caveats apply.
 */
#if IMG4_TARGET_DARWIN
IMG4_API_AVAILABLE_20200508
OS_EXPORT OS_WARN_RESULT OS_MALLOC OS_NONNULL1 OS_NONNULL2
img4_firmware_t
img4_firmware_new_from_fd_4MSM(const img4_runtime_t *rt,
		const img4_firmware_execution_context_t *exec,
		img4_4cc_t _4cc,
		os_fd_t *fd,
		img4_firmware_flags_t flags);
#endif

/*!
 * @function img4_firmware_init_from_buff
 * Initializes a buffer as a firmware object. This interface is useful for
 * runtimes which do not provide for dynamic memory allocation.
 *
 * @param storage
 * A pointer to the storage to use for the firmware object.
 *
 * @param len
 * The size of the buffer.
 *
 * @discussion
 * The caller is expected to pass a buffer that is "big enough". If the provided
 * buffer is too small, the implementation will abort the caller.
 *
 * @example
 *
 *     uint8_t _buff[IMG4_FIRMWARE_SIZE_RECOMMENDED];
 *     img4_firmware_t fw = NULL;
 *
 *     fw = img4_firmware_init_from_buff(_buff, sizeof(_buff));
 *     img4_firmware_init(fw, IMG4_RUNTIME_DEFAULT, &exec_context,
 *             kImg4Tag_krnl, fw_buff, 0);
 */
#if !XNU_KERNEL_PRIVATE
IMG4_API_AVAILABLE_20200508
OS_EXPORT OS_WARN_RESULT OS_NONNULL1
img4_firmware_t
img4_firmware_init_from_buff(void *buff, size_t len);
#else
#define img4_firmware_init_from_buff(...) \
		(img4if->i4if_v7.firmware_init_from_buff(__VA_ARGS__))
#endif

/*!
 * @function img4_firmware_init
 * Initialize a firmware object.
 *
 * @param fw
 * A pointer to the storage for the firmware object. This pointer should refer
 * to a region of memory that is sufficient to hold a {@link img4_firmware_t}
 * object. This size should be queried with the {@link i4rt_object_size}
 * function of the runtime.
 *
 * @param rt
 * The runtime in which to initialize the object.
 *
 * @param _4cc
 * The 4cc which distinguishes the firmware.
 *
 * @param buff
 * A buffer containing a valid Image4 payload (usually the contents of either a
 * .im4p or .img4 file).
 *
 * Upon return, the destructor in the buffer is replaced with NULL, and the
 * implementation assumes responsibility for deallocating the underlying memory.
 *
 * @param flags
 * Flags modifying the behavior of the object.
 *
 * @discussion
 * The resulting object assumes ownership of the given buffer. This routine
 * should only be used when dynamic memory allocation is not available in the
 * runtime. Otherwise, use {@link img4_firmware_new}.
 */
#if !XNU_KERNEL_PRIVATE
IMG4_API_AVAILABLE_20200508
OS_EXPORT OS_NONNULL1 OS_NONNULL2 OS_NONNULL3 OS_NONNULL5
void
img4_firmware_init(img4_firmware_t fw,
		const img4_runtime_t *rt,
		const img4_firmware_execution_context_t *exec,
		img4_4cc_t _4cc,
		img4_buff_t *buff,
		img4_firmware_flags_t flags);
#else
#define img4_firmware_init(...) (img4if->i4if_v7.firmware_init(__VA_ARGS__))
#endif

/*!
 * @function img4_firmware_init_sentinel
 * Initialize a firmware object as a sentinel without any manifest attached.
 * This firmware has no object tag and is not executable. It is only suitable
 * for use with {@link img4_firmware_attach_manifest} and
 * {@link img4_firmware_evaluate} to determine whether a manifest is acceptable
 * to a particular chip environment.
 *
 * @param fw
 * A pointer to the storage for the firmware object. This pointer should refer
 * to a region of memory that is sufficient to hold a {@link img4_firmware_t}
 * object. This size should be queried with the {@link i4rt_object_size}
 * function of the runtime.
 *
 * @param rt
 * The runtime in which to initialize the object.
 *
 * @param flags
 * Flags modifying the behavior of the object.
 *
 * @discussion
 * Sentinel firmwares do not enforce anti-replay, so
 * {@link img4_firmware_evaluate} will not return ESTALE when evaluating such
 * firmwares. Anti-replay enforcement can be enabled by using
 * {@link IMG4_FIRMWARE_FLAG_FORCE_ANTI_REPLAY}.
 */
#if !XNU_KERNEL_PRIVATE
IMG4_API_AVAILABLE_20211126
OS_EXPORT OS_NONNULL1 OS_NONNULL2
void
img4_firmware_init_sentinel(img4_firmware_t fw,
		const img4_runtime_t *rt,
		img4_firmware_flags_t flags);
#else
#define img4_firmware_init_sentinel(...) \
		(img4if->i4if_v17.firmware_init_sentinel(__VA_ARGS__))
#endif

/*!
 * @function img4_firmware_attach_manifest
 * Attaches a signed manifest to the firmware.
 *
 * @param fw
 * The firmware to manipulate.
 *
 * @param buff
 * A buffer containing a valid Image4 manifest (usually the contents of either a
 * .im4m or .img4 file).
 *
 * Upon return, the destructor in the buffer is replaced with NULL, and the
 * implementation assumes responsibility for deallocating the underlying memory.
 *
 * @discussion
 * If this interface is called on a firmware created with the
 * {@link IMG4_FIRMWARE_FLAG_ATTACHED_MANIFEST} flag, the implementation's
 * behavior is undefined.
 *
 * This interface must be called on any firmware created with the
 * {@link IMG4_FIRMWARE_FLAG_BARE} flag.
 *
 * The object assumes ownership of the given buffer.
 */
#if !XNU_KERNEL_PRIVATE
IMG4_API_AVAILABLE_20200508
OS_EXPORT OS_NONNULL1 OS_NONNULL2
void
img4_firmware_attach_manifest(img4_firmware_t fw,
		img4_buff_t *buff);
#else
#define img4_firmware_attach_manifest(...) \
		(img4if->i4if_v7.firmware_attach_manifest(__VA_ARGS__))
#endif

/*!
 * @function img4_firmware_select_chip
 * Returns the chip from the provided array which may be used to authenticate
 * the firmware.
 *
 * @param fw
 * The firmware to query.
 *
 * @param acceptable_chips
 * An array of chips the caller finds acceptable to verify the firmware.
 *
 * @param acceptable_chips_cnt
 * The number of elements in {@link acceptable_chips}.
 *
 * @result
 * If the manifest may be authenticated by the certificate chain associated with
 * one of the manifests provided in {@link acceptable_chips}, that chip is
 * returned. If the manifest cannot be authenticated with any of the provided
 * chips, NULL is returned.
 *
 * @discussion
 * The result of calling this function on a firmware which does not have a
 * manifest attached is undefined.
 *
 * If multiple chips may be used to authenticate the firmware, the
 * implementation does not define which of those chips will be returned.
 *
 * If the firmware was created without the
 * {@link IMG4_FIRMWARE_FLAG_SUBSEQUENT_STAGE} flag, this function will return
 * NULL. This function cannot be used to establish new trust chains, only to
 * verify an existing one.
 */
#if !XNU_KERNEL_PRIVATE
IMG4_API_AVAILABLE_20200724
OS_EXPORT OS_WARN_RESULT
const img4_chip_t *_Nullable
img4_firmware_select_chip(const img4_firmware_t fw,
		const img4_chip_select_array_t _Nonnull acceptable_chips,
		size_t acceptable_chips_cnt);
#else
#define img4_firmware_select_chip(...) \
		(img4if->i4if_v10.firmware_select_chip(__VA_ARGS__))
#endif

/*!
 * @function img4_firmware_execute
 * Authenticate the firmware and execute it within its context.
 *
 * @param fw
 * The firmware to execute.
 *
 * @param chip
 * The chip on which to execute the firmware.
 *
 * @param nonce
 * The nonce to use for authentication. May be NULL if the chip environment does
 * not maintain an anti-replay token or if a chained evaluation is being
 * performed.
 *
 * @discussion
 * The implementation will always invoke the
 * {@link img4_firmware_authenticated_execute_t} provided in the execution
 * context with either a successful result or a failure. All error handling must
 * take place in that context.
 *
 * The {@link img4_firmware_authenticated_execute_t} is called before the
 * implementation returns.
 *
 * The result of executing a firmware without a manifest attached (either via
 * {@link img4_firmware_attach_manifest} or by creating the firmware with the
 * {@link IMG4_FIRMWARE_FLAG_ATTACHED_MANIFEST} flag set) is undefined.
 */
#if !XNU_KERNEL_PRIVATE
IMG4_API_AVAILABLE_20200508
OS_EXPORT OS_NONNULL1 OS_NONNULL2
void
img4_firmware_execute(img4_firmware_t fw,
		const img4_chip_t *chip,
		const img4_nonce_t *_Nullable nonce);
#else
#define img4_firmware_execute(...) \
		(img4if->i4if_v7.firmware_execute(__VA_ARGS__))
#endif

/*!
 * @function img4_firmware_evaluate
 * Evaluate the firmware for authenticity.
 *
 * @param fw
 * The firmware to evaluate.
 *
 * @param chip
 * The chip on which to evaluate the firmware.
 *
 * @param nonce
 * The nonce to use for authentication. May be NULL if the chip environment does
 * not maintain an anti-replay token or if a chained evaluation is being
 * performed.
 *
 * @result
 * An error code describing the result of the authentication. If authentication
 * was successful, zero is returned. Otherwise, one of the following error codes
 * will be returned:
 *
 *     [EILSEQ]     The firmware data is not valid Image4 data -- this will not
 *                  be returned for firmwares created with
 *                  {@link IMG4_FIRMWARE_FLAG_BARE}
 *     [EFTYPE]     The attached manifest is not a valid Image4 manifest
 *     [ENOENT]     The attached manifest does not authenticate this type of
 *                  firmware
 *     [EAUTH]      The attached manifest is not authentic (i.e. was not signed
 *                  by an Apple CA)
 *     [EACCES]     The given chip does not satisfy the constraints of the
 *                  attached manifest
 *     [ESTALE]     The manifest has been invalidated and is no longer valid for
 *                  the provided chip
 *     [ENOEXEC]    The firmware has been corrupted, or the given chip does not
 *                  satisfy the constraints of the corresponding object in the
 *                  attached manifest
 *     [EPWROFF]    The chip environment has not yet booted; most chip
 *                  environments are booted and available by the time the caller
 *                  has begun executing, but some require additional
 *                  initialization before they can execute objects
 *
 * @discussion
 * This interface should be used when the caller is only concerned with the
 * authenticity and integrity of the firmware image and does not intend to
 * execute it.
 *
 * The result of evaluating a firmware without a manifest attached (either via
 * {@link img4_firmware_attach_manifest} or by creating the firmware with the
 * {@link IMG4_FIRMWARE_FLAG_ATTACHED_MANIFEST} flag set) is undefined.
 */
#if !XNU_KERNEL_PRIVATE
IMG4_API_AVAILABLE_20200608
OS_EXPORT OS_WARN_RESULT OS_NONNULL1 OS_NONNULL2
errno_t
img4_firmware_evaluate(img4_firmware_t fw,
		const img4_chip_t *chip,
		const img4_nonce_t *_Nullable nonce);
#else
#define img4_firmware_evaluate(...) \
		(img4if->i4if_v9.firmware_evaluate(__VA_ARGS__))
#endif

/*!
 * @function img4_firmware_destroy
 * Destroys a firmware object and releases the associated resources according to
 * the runtime's specification.
 *
 * @param fw
 * A pointer to the firmware object.
 *
 * Upon return, this will be replaced with a known-invalid pointer value. This
 * parameter may be NULL in which case the implementation will return
 * immediately.
 *
 * @discussion
 * The implementation will invoke the provided deallocation function of the
 * buffer object underlying the firmware.
 */
#if !XNU_KERNEL_PRIVATE
IMG4_API_AVAILABLE_20200508
OS_EXPORT
void
img4_firmware_destroy(img4_firmware_t _Nonnull *_Nullable fw);
#else
#define img4_firmware_destroy(...) \
		(img4if->i4if_v7.firmware_destroy(__VA_ARGS__))
#endif

OS_ASSUME_NONNULL_END
__END_DECLS

#endif // __IMG4_FIRMWARE_H
STAGEEOF
    echo "Staged img4/firmware.h (no KDK)"
fi
if [ ! -f "EXTERNAL_HEADERS/img4/image.h" ]; then
    mkdir -p "EXTERNAL_HEADERS/img4"
    cat > "EXTERNAL_HEADERS/img4/image.h" <<'STAGEEOF'
/*!
 * @header
 * Interfaces for manipulating Image4 firmware images.
 */
#ifndef __IMG4_IMAGE_H
#define __IMG4_IMAGE_H

#ifndef __IMG4_INDIRECT
#error "Please #include <img4/firmware.h> instead of this file directly"
#endif // __IMG4_INDIRECT

OS_ASSUME_NONNULL_BEGIN

/*!
 * @function img4_image_get_bytes
 * Returns the authenticated payload from an Image4 image.
 *
 * @param image
 * The image to query. May be NULL.
 *
 * @result
 * A buffer which describes the authenticated payload. If the payload was not
 * authenticated, NULL is returned.
 */
#if !XNU_KERNEL_PRIVATE
IMG4_API_AVAILABLE_20200508
OS_EXPORT OS_WARN_RESULT
const img4_buff_t *_Nullable
img4_image_get_bytes(img4_image_t _Nullable image);
#else
#define img4_image_get_bytes(...) (img4if->i4if_v7.image_get_bytes(__VA_ARGS__))
#endif

/*!
 * @function img4_image_get_property_bool
 * Retrieves the Boolean value for the requested image property.
 *
 * @param image
 * The image to query.
 *
 * @param _4cc
 * The 4cc of the desired image property.
 *
 * @param storage
 * A pointer to storage for a Boolean value.
 *
 * @result
 * If the property is present for the image, a pointer to the storage provided
 * in {@link storage}. If the property is not present in the image or its value
 * is not a Boolean, NULL is returned.
 */
#if !XNU_KERNEL_PRIVATE
IMG4_API_AVAILABLE_20200508
OS_EXPORT OS_WARN_RESULT OS_NONNULL1 OS_NONNULL3
const bool *
img4_image_get_property_bool(img4_image_t image,
		img4_4cc_t _4cc,
		bool *storage);
#else
#define img4_image_get_property_bool(...) \
		(img4if->i4if_v7.image_get_property_bool(__VA_ARGS__))
#endif

/*!
 * @function img4_image_get_property_uint32
 * Retrieves the unsigned 32-bit integer value for the requested image property.
 *
 * @param image
 * The image to query.
 *
 * @param _4cc
 * The 4cc of the desired image property.
 *
 * @param storage
 * A pointer to storage for a 32-bit unsigned integer value.
 *
 * @result
 * If the property is present for the image, a pointer to the storage provided
 * in {@link storage}. If the property is not present in the image or its value
 * is not an unsigned 32-bit integer, NULL is returned.
 */
#if !XNU_KERNEL_PRIVATE
IMG4_API_AVAILABLE_20200508
OS_EXPORT OS_WARN_RESULT OS_NONNULL1 OS_NONNULL3
const uint32_t *
img4_image_get_property_uint32(img4_image_t image,
		img4_4cc_t _4cc,
		uint32_t *storage);
#else
#define img4_image_get_property_uint32(...) \
		(img4if->i4if_v7.image_get_property_uint32(__VA_ARGS__))
#endif

/*!
 * @function img4_image_get_property_uint64
 * Retrieves the unsigned 64-bit integer value for the requested image property.
 *
 * @param image
 * The image to query.
 *
 * @param _4cc
 * The 4cc of the desired image property.
 *
 * @param storage
 * A pointer to storage for a 64-bit unsigned integer value.
 *
 * @result
 * If the property is present for the image, a pointer to the storage provided
 * in {@link storage}. If the property is not present in the image or its value
 * is not an unsigned 64-bit integer, NULL is returned.
 */
#if !XNU_KERNEL_PRIVATE
IMG4_API_AVAILABLE_20200508
OS_EXPORT OS_WARN_RESULT OS_NONNULL1 OS_NONNULL3
const uint64_t *
img4_image_get_property_uint64(img4_image_t image,
		img4_4cc_t _4cc,
		uint64_t *storage);
#else
#define img4_image_get_property_uint64(...) \
		(img4if->i4if_v7.image_get_property_uint64(__VA_ARGS__))
#endif

/*!
 * @function img4_image_get_property_data
 * Retrieves the buffer value for the requested image property.
 *
 * @param image
 * The image to query.
 *
 * @param _4cc
 * The 4cc of the desired image property.
 *
 * @param storage
 * A pointer to storage for a buffer value.
 *
 * @result
 * If the property is present for the image, a pointer to the storage provided
 * in {@link storage}. If the property is not present in the image or its value
 * is not a data, NULL is returned.
 */
#if !XNU_KERNEL_PRIVATE
IMG4_API_AVAILABLE_20200508
OS_EXPORT OS_WARN_RESULT OS_NONNULL1 OS_NONNULL3
const img4_buff_t *
img4_image_get_property_data(img4_image_t image,
		img4_4cc_t _4cc,
		img4_buff_t *storage);
#else
#define img4_image_get_property_data(...) \
		(img4if->i4if_v7.image_get_property_data(__VA_ARGS__))
#endif

/*!
 * @function img4_image_get_entitlement_bool
 * Retrieves the Boolean value for the requested image entitlement.
 *
 * @param image
 * The image to query.
 *
 * @param _4cc
 * The 4cc of the desired image entitlement.
 *
 * @param storage
 * A pointer to storage for a Boolean value.
 *
 * @result
 * If the  entitlement is present for the image, a pointer to the storage
 * provided in {@link storage}. If the property is not present in the image or
 * its value is not a Boolean, NULL is returned.
 */
#if !XNU_KERNEL_PRIVATE
IMG4_API_AVAILABLE_20220513
OS_EXPORT OS_WARN_RESULT OS_NONNULL1 OS_NONNULL3
const bool *
img4_image_get_entitlement_bool(img4_image_t image,
		img4_4cc_t _4cc,
		bool *storage);
#else
#define img4_image_get_entitlement_bool(...) \
		(img4if->i4if_v18.image_get_entitlement_bool(__VA_ARGS__))
#endif

/*!
 * @function img4_image_get_entitlement_uint32
 * Retrieves the unsigned 32-bit integer value for the requested image
 * entitlement.
 *
 * @param image
 * The image to query.
 *
 * @param _4cc
 * The 4cc of the desired image entitlement.
 *
 * @param storage
 * A pointer to storage for a 32-bit unsigned integer value.
 *
 * @result
 * If the entitlement is present for the image, a pointer to the storage
 * provided in {@link storage}. If the property is not present in the image or
 * its value is not an unsigned 32-bit integer, NULL is returned.
 */
#if !XNU_KERNEL_PRIVATE
IMG4_API_AVAILABLE_20220513
OS_EXPORT OS_WARN_RESULT OS_NONNULL1 OS_NONNULL3
const uint32_t *
img4_image_get_entitlement_uint32(img4_image_t image,
		img4_4cc_t _4cc,
		uint32_t *storage);
#else
#define img4_image_get_entitlement_uint32(...) \
		(img4if->i4if_v18.image_get_entitlement_uint32(__VA_ARGS__))
#endif

/*!
 * @function img4_image_get_entitlement_uint64
 * Retrieves the unsigned 64-bit integer value for the requested image
 * entitlement.
 *
 * @param image
 * The image to query.
 *
 * @param _4cc
 * The 4cc of the desired image entitlement.
 *
 * @param storage
 * A pointer to storage for a 64-bit unsigned integer value.
 *
 * @result
 * If the entitlement is present for the image, a pointer to the storage
 * provided in {@link storage}. If the property is not present in the image or
 * its value is not an unsigned 64-bit integer, NULL is returned.
 */
#if !XNU_KERNEL_PRIVATE
IMG4_API_AVAILABLE_20220513
OS_EXPORT OS_WARN_RESULT OS_NONNULL1 OS_NONNULL3
const uint64_t *
img4_image_get_entitlement_uint64(img4_image_t image,
		img4_4cc_t _4cc,
		uint64_t *storage);
#else
#define img4_image_get_entitlement_uint64(...) \
		(img4if->i4if_v18.image_get_entitlement_uint64(__VA_ARGS__))
#endif

/*!
 * @function img4_image_get_entitlement_data
 * Retrieves the buffer value for the requested image entitlement.
 *
 * @param image
 * The image to query.
 *
 * @param _4cc
 * The 4cc of the desired image entitlement.
 *
 * @param storage
 * A pointer to storage for a buffer value.
 *
 * @result
 * If the entitlement is present for the image, a pointer to the storage
 * provided in {@link storage}. If the property is not present in the image or
 * its value is not a data, NULL is returned.
 */
#if !XNU_KERNEL_PRIVATE
IMG4_API_AVAILABLE_20220513
OS_EXPORT OS_WARN_RESULT OS_NONNULL1 OS_NONNULL3
const img4_buff_t *
img4_image_get_entitlement_data(img4_image_t image,
		img4_4cc_t _4cc,
		img4_buff_t *storage);
#else
#define img4_image_get_entitlement_data(...) \
		(img4if->i4if_v18.image_get_entitlement_data(__VA_ARGS__))
#endif

OS_ASSUME_NONNULL_END

#endif // __IMG4_IMAGE_H
STAGEEOF
    echo "Staged img4/image.h (no KDK)"
fi
if [ ! -f "EXTERNAL_HEADERS/img4/nonce.h" ]; then
    mkdir -p "EXTERNAL_HEADERS/img4"
    cat > "EXTERNAL_HEADERS/img4/nonce.h" <<'STAGEEOF'
/*!
 * @header
 * Provides an interface for managing nonces to govern the lifetime of a
 * personalization performed with TSS. A nonce managed by this interface may
 * be used in a TSS signing request as the value for the BNCH tag.
 *
 * These interfaces require the caller to possess the
 *
 *     com.apple.private.security.AppleImage4.user-client
 *
 * entitlement.
 *
 * @section Threat Model
 * The adversary possesses the following:
 *
 *     1. a manifest which was previously valid but has since been invalidated
 *        by rolling the nonce associated with it
 *     2. user-level code execution
 *     3. knowledge of the raw nonce value for the previously-valid manifest
 *
 * The defense against this adversary is a system in which knowledge of the raw
 * nonce is insufficient to impact the evaluation of a personalization. This
 * system has the following characteristics:
 *
 *     1. A nonce seed is stored in an nvram variable which is only writable by
 *        the kernel
 *     2. When making a new signing request, the nonce seed is encrypted by a
 *        UID1-derived key in-kernel and then hashed -- the output of this
 *        operation the nonce to be used in the signing request
 *     3. On boot, AppleImage4 obtains the nonce seed from nvram and stores it
 *        in a data structure which will be covered by KTRR
 *     4. When evaluating a manifest, AppleImage4 reads the raw nonce from the
 *        KTRR-covered data structure and validates it with the same
 *        transformation as was done in (2)
 *     5. When the nonce is to be invalidated, AppleImage4 sets a flag in an
 *        nvram variable which is only writable by the kernel
 *     6. On the subsequent boot, AppleImage4 notices the flag, generates a new
 *        nonce and repeats the procedure in (3)
 *
 * In this system, the raw nonce seed never leaves the kernel, and the nonce
 * itself is a non-reversible representation of the seed.
 */


#ifndef __IMG4_NONCE_H
#define __IMG4_NONCE_H

#ifndef __IMG4_INDIRECT
#error "Please #include <img4/firmware.h> instead of this file directly"
#endif // __IMG4_INDIRECT

/*!
 * @typedef img4_nonce_domain_t
 * An opaque type describing a nonce domain.
 */
IMG4_API_AVAILABLE_20181106
typedef struct _img4_nonce_domain img4_nonce_domain_t;

/*!
 * @const IMG4_NONCE_STRUCT_VERSION
 * The version of the {@link img4_nonce_t} structure supported by the
 * implementation.
 */
#define IMG4_NONCE_STRUCT_VERSION ((img4_struct_version_t)0)
#define IMG4_NONCE_VERSION IMG4_NONCE_STRUCT_VERSION

/*!
 * @const IMG4_NONCE_MAX_LENGTH
 * The maximum length of a nonce. Currently, this is the length of a SHA2-384
 * hash.
 */
#define IMG4_NONCE_MAX_LENGTH (48u)

/*!
 * @typedef img4_nonce_domain_index_t
 * An enumeration describing nonce domains.
 *
 * @const IMG4_NONCE_DOMAIN_INDEX_TEST
 * The enumerated constant corresponding to the internal test nonce domain.
 *
 * @const IMG4_NONCE_DOMAIN_INDEX_TRUST_CACHE
 * The enumerated constant corresponding to
 * {@link IMG4_NONCE_DOMAIN_TRUST_CACHE}.
 *
 * @const IMG4_NONCE_DOMAIN_INDEX_PDI
 * The enumerated constant corresponding to {@link IMG4_NONCE_DOMAIN_TRUST_PDI}.
 *
 * @const IMG4_NONCE_DOMAIN_INDEX_CRYPTEX
 * The enumerated constant corresponding to {@link IMG4_NONCE_DOMAIN_CRYPTEX}.
 *
 * @const IMG4_NONCE_DOMAIN_INDEX_DDI
 * The enumerated constant corresponding to {@link IMG4_NONCE_DOMAIN_DDI}.
 *
 * @const IMG4_NONCE_DOMAIN_INDEX_EPHEMERAL_CRYPTEX
 * The enumerated constant corresponding to
 * {@link IMG4_NONCE_DOMAIN_EPHEMERAL_CRYPTEX}.
 *
 * @const IMG4_NONCE_DOMAIN_INDEX_CRYPTEX1_SNUF_STUB
 * The enumerated constant corresponding to
 * {@link IMG4_NONCE_DOMAIN_CRYPTEX1_SNUF_STUB}.
 *
 * @const IMG4_NONCE_DOMAIN_INDEX_CRYPTEX1_BOOT
 * The enumerated constant corresponding to
 * {@link IMG4_NONCE_DOMAIN_CRYPTEX1_BOOT}.
 *
 * @const IMG4_NONCE_DOMAIN_INDEX_CRYPTEX1_ASSET
 * The enumerated constant corresponding to
 * {@link IMG4_NONCE_DOMAIN_CRYPTEX1_ASSET}.
 *
 * @const _IMG4_NONCE_DOMAIN_INDEX_CNT
 * A sentinel value indicating the number of nonce domains.
 */
IMG4_API_AVAILABLE_20210521
OS_CLOSED_ENUM(img4_nonce_domain_index, uint64_t,
	IMG4_NONCE_DOMAIN_INDEX_TEST = 0,
	IMG4_NONCE_DOMAIN_INDEX_TRUST_CACHE,
	IMG4_NONCE_DOMAIN_INDEX_PDI,
	IMG4_NONCE_DOMAIN_INDEX_CRYPTEX,
	IMG4_NONCE_DOMAIN_INDEX_DDI,
	IMG4_NONCE_DOMAIN_INDEX_EPHEMERAL_CRYPTEX,
	IMG4_NONCE_DOMAIN_INDEX_CRYPTEX1_SNUF_STUB,
	IMG4_NONCE_DOMAIN_INDEX_CRYPTEX1_BOOT,
	IMG4_NONCE_DOMAIN_INDEX_CRYPTEX1_ASSET,
	_IMG4_NONCE_DOMAIN_INDEX_CNT,
);

/*!
 * @typedef img4_nonce_t
 * A structure describing a nonce.
 *
 * @field i4n_version
 * The version of the structure. When declaring this structure, you must
 * initialize this field to {@link IMG4_NONCE_VERSION}.
 *
 * @field i4n_nonce
 * The bytes comprising the nonce.
 *
 * @field i4n_length
 * The length of the nonce. Will be at most {@link IMG4_NONCE_MAX_LENGTH}.
 *
 * @discussion
 * The {@link i4n_nonce} field was previously const. This was a terrible idea,
 * and the const storage qualifier was removed without adjusting the structure
 * version.
 */
IMG4_API_AVAILABLE_20181106
typedef struct _img4_nonce {
	img4_struct_version_t i4n_version;
	uint8_t i4n_nonce[IMG4_NONCE_MAX_LENGTH];
	uint32_t i4n_length;
} img4_nonce_t;

/*!
 * @const IMG4_NONCE_INIT
 * A convenience initializer for {@link img4_nonce_t} which ensures that the
 * {@link i4n_version} field is properly initialized.
 */
#if defined(__STDC_VERSION__) && __STDC_VERSION__ >= 199901L
#define IMG4_NONCE_INIT (img4_nonce_t){.i4n_version = IMG4_NONCE_STRUCT_VERSION}
#elif defined(__cplusplus) && __cplusplus >= 201103L
#define IMG4_NONCE_INIT (img4_nonce_t{IMG4_NONCE_STRUCT_VERSION})
#elif defined(__cplusplus)
#define IMG4_NONCE_INIT \
		(img4_nonce_t((img4_nonce_t){IMG4_NONCE_STRUCT_VERSION}))
#else
#define IMG4_NONCE_INIT {IMG4_NONCE_STRUCT_VERSION}
#endif

/*!
 * @const IMG4_NONCE_ZERO
 * A convenience initializer for {@link img4_nonce_t} which initializes a 48-
 * byte nonce of all zeroes.
 */
#if defined(__STDC_VERSION__) && __STDC_VERSION__ >= 199901L
#define IMG4_NONCE_ZERO (img4_nonce_t){ \
	.i4n_version = IMG4_NONCE_STRUCT_VERSION, \
	.i4n_nonce = {0}, \
	.i4n_length = IMG4_NONCE_MAX_LENGTH, \
}
#endif

/*!
 * @const IMG4_NONCE_DOMAIN_TRUST_CACHE
 * The nonce domain governing trust cache personalizations. Use of this domain
 * requires the
 *
 *     com.apple.private.img4.nonce.trust-cache
 *
 * entitlement.
 */
#if !XNU_KERNEL_PRIVATE
IMG4_API_AVAILABLE_20181106
OS_EXPORT
const struct _img4_nonce_domain _img4_nonce_domain_trust_cache;
#define IMG4_NONCE_DOMAIN_TRUST_CACHE (&_img4_nonce_domain_trust_cache)
#else
#define IMG4_NONCE_DOMAIN_TRUST_CACHE (img4if->i4if_v1.nonce_domain_trust_cache)
#endif

/*!
 * @const IMG4_NONCE_DOMAIN_PDI
 * The nonce domain governing disk image personalizations. Use of this domain
 * requires the
 *
 *     com.apple.private.img4.nonce.pdi
 *
 * entitlement. The nonce for this domain is regenerated once every boot.
 */
#if !XNU_KERNEL_PRIVATE
IMG4_API_AVAILABLE_20181106
OS_EXPORT
const struct _img4_nonce_domain _img4_nonce_domain_pdi;
#define IMG4_NONCE_DOMAIN_PDI (&_img4_nonce_domain_pdi)
#else
#define IMG4_NONCE_DOMAIN_PDI (img4if->i4if_v3.nonce_domain_pdi)
#endif

/*!
 * @const IMG4_NONCE_DOMAIN_CRYPTEX
 * The nonce domain governing cryptex personalizations. Use of this domain
 * requires the
 *
 *     com.apple.private.img4.nonce.cryptex
 *
 * entitlement.
 */
#if !XNU_KERNEL_PRIVATE
IMG4_API_AVAILABLE_20181106
OS_EXPORT
const struct _img4_nonce_domain _img4_nonce_domain_cryptex;
#define IMG4_NONCE_DOMAIN_CRYPTEX (&_img4_nonce_domain_cryptex)
#else
#define IMG4_NONCE_DOMAIN_CRYPTEX (img4if->i4if_v3.nonce_domain_cryptex)
#endif

/*!
 * @const IMG4_NONCE_DOMAIN_DDI
 * The nonce domain governing developer disk image personalizations. Use of this
 * domain requires the
 *
 *     com.apple.private.img4.nonce.ddi
 *
 * entitlement.
 */
#if !XNU_KERNEL_PRIVATE
IMG4_API_AVAILABLE_20181106
OS_EXPORT
const struct _img4_nonce_domain _img4_nonce_domain_ddi;
#define IMG4_NONCE_DOMAIN_DDI (&_img4_nonce_domain_ddi)
#else
#define IMG4_NONCE_DOMAIN_DDI (img4if->i4if_v12.nonce_domain_ddi)
#endif

/*!
 * @const IMG4_NONCE_DOMAIN_EPHEMERAL_CRYPTEX
 * The nonce domain governing ephemeral cryptex personalizations. Use of this
 * domain requires the
 *
 *     com.apple.private.img4.nonce.ephemeral-cryptex
 *
 * entitlement.
 */
#if !XNU_KERNEL_PRIVATE
IMG4_API_AVAILABLE_20210305
OS_EXPORT
const struct _img4_nonce_domain _img4_nonce_domain_ephemeral_cryptex;
#define IMG4_NONCE_DOMAIN_EPHEMERAL_CRYPTEX \
		(&_img4_nonce_domain_ephemeral_cryptex)
#else
#define IMG4_NONCE_DOMAIN_EPHEMERAL_CRYPTEX \
		(img4if->i4if_v12.nonce_domain_ephemeral_cryptex)
#endif

/*!
 * @const IMG4_NONCE_DOMAIN_CRYPTEX1_SNUF_STUB
 * The nonce domain which acts as a null stub for the snuf value for Cryptex1
 * processors. This domain corresponds to a value of 0 for the
 * Cryptex1,NonceDomain tag. Use of this domain requires the
 *
 *     com.apple.private.img4.nonce.cryptex1.snuf-stub
 *
 * entitlement.
 */
#if !XNU_KERNEL_PRIVATE
IMG4_API_AVAILABLE_20220322
OS_EXPORT
const struct _img4_nonce_domain _img4_nonce_domain_cryptex1_snuf_stub;
#define IMG4_NONCE_DOMAIN_CRYPTEX1_SNUF_STUB \
		(&_img4_nonce_domain_cryptex1_snuf_stub)
#else
#define IMG4_NONCE_DOMAIN_CRYPTEX1_SNUF_STUB \
		(img4if->i4if_v18.nonce_domain_cryptex1_snuf_stub)
#endif

/*!
 * @const IMG4_NONCE_DOMAIN_CRYPTEX1_BOOT
 * The nonce domain governing personalizations for the virtual Cryptex1
 * coprocessor's boot objects. This domain corresponds to a value of 1 for the
 * Cryptex1,NonceDomain tag. Use of this domain requires the
 *
 *     com.apple.private.img4.nonce.cryptex1.boot
 *
 * entitlement.
 */
#if !XNU_KERNEL_PRIVATE
IMG4_API_AVAILABLE_20211112
OS_EXPORT
const struct _img4_nonce_domain _img4_nonce_domain_cryptex1_boot;
#define IMG4_NONCE_DOMAIN_CRYPTEX1_BOOT \
		(&_img4_nonce_domain_cryptex1_boot)
#else
#define IMG4_NONCE_DOMAIN_CRYPTEX1_BOOT \
		(img4if->i4if_v16.nonce_domain_cryptex1_boot)
#endif

/*!
 * @const IMG4_NONCE_DOMAIN_CRYPTEX1_ASSET
 * The nonce domain governing personalizations for the virtual Cryptex1
 * coprocessor's asset brain objects. This domain corresponds to a value of 2
 * for the Cryptex1,NonceDomain tag. Use of this domain requires the
 *
 *     com.apple.private.img4.nonce.cryptex1.asset
 *
 * entitlement.
 */
#if !XNU_KERNEL_PRIVATE
IMG4_API_AVAILABLE_20211112
OS_EXPORT
const struct _img4_nonce_domain _img4_nonce_domain_cryptex1_asset;
#define IMG4_NONCE_DOMAIN_CRYPTEX1_ASSET \
		(&_img4_nonce_domain_cryptex1_asset)
#else
#define IMG4_NONCE_DOMAIN_CRYPTEX1_ASSET \
		(img4if->i4if_v16.nonce_domain_cryptex1_asset)
#endif

/*!
 * @function img4_nonce_domain_copy_nonce
 * Copies the current value of the nonce in the given domain.
 *
 * @param nd
 * The nonce domain.
 *
 * @param n
 * Upon successful return, storage that will contain the current nonce. The
 * provided structure's {@link i4n_version} must be initialized to
 * {@link IMG4_NONCE_VERSION}.
 *
 * @result
 * Upon success, zero is returned. The implementation may also return one of the
 * following error codes directly:
 *
 *     [ESTALE]     The nonce for the given domain has been invalidated, and the
 *                  host must reboot in order to generate a new one
 *     [EPERM]      The caller lacked the entitlement necessary to read the
 *                  given nonce
 *     [ENOTSUP]    Nonce management is not available on the host
 *     [EACCES]     The nonce requested is not accessible in this environment
 */
#if !XNU_KERNEL_PRIVATE
IMG4_API_AVAILABLE_20210305
OS_EXPORT OS_WARN_RESULT OS_NONNULL1 OS_NONNULL2
errno_t
img4_nonce_domain_copy_nonce(const img4_nonce_domain_t *nd, img4_nonce_t *n);
#else
#define img4_nonce_domain_copy_nonce(...) \
		(img4if->i4if_v1.nonce_domain_copy_nonce(__VA_ARGS__))
#endif

/*!
 * @function img4_nonce_domain_roll_nonce
 * Invalidates the current nonce for the given domain and forces a re-generation
 * of the domain's nonce seed at the next boot.
 *
 * @param nd
 * The nonce domain.
 *
 * @result
 * Upon success, zero is returned. The kernel implementation will never return
 * a non-zero code. The userspace implementation may return one of the following
 * error codes directly:
 *
 *     [EPERM]      The caller lacked the entitlement necessary to roll the
 *                  given nonce
 *     [EROFS]      The boot mode didn't allow committing to non-volatile storage
 *     [ENOTSUP]    Nonce management is not available on the host
 *     [EACCES]     The nonce requested is not accessible in this environment
 */
#if !XNU_KERNEL_PRIVATE
IMG4_API_AVAILABLE_20181106
OS_EXPORT OS_WARN_RESULT OS_NONNULL1
errno_t
img4_nonce_domain_roll_nonce(const img4_nonce_domain_t *nd);
#else
#define img4_nonce_domain_roll_nonce(...) \
		(img4if->i4if_v1.nonce_domain_roll_nonce(__VA_ARGS__))
#endif

/*!
 * @function img4_nonce_domain_preroll_nonce
 * Generates a new nonce seed and returns the resulting hash. The new nonce seed
 * will be in force at the next reboot if and only if the boot manifest hash
 * changes. Otherwise, the current nonce seed value will remain stable (modulo
 * the regeneration policy associated with its domain).
 *
 * @param nd
 * The nonce domain.
 *
 * @param n
 * Upon successful return, storage that will contain the current nonce. The
 * provided structure's {@link i4n_version} must be initialized to
 * {@link IMG4_NONCE_VERSION}.
 *
 * @result
 * Upon success, zero is returned. The kernel implementation will never return
 * a non-zero code. The userspace implementation may return one of the following
 * error codes directly:
 *
 *     [EPERM]      The caller lacked the entitlement necessary to roll the
 *                  given nonce
 *     [EROFS]      The boot mode didn't allow committing to non-volatile storage
 *     [ENOTSUP]    Nonce management is not available on the host
 *     [EACCES]     The nonce requested is not accessible in this environment
 */
#if !XNU_KERNEL_PRIVATE
IMG4_API_AVAILABLE_FALL_2021_B
OS_EXPORT OS_WARN_RESULT OS_NONNULL1 OS_NONNULL2
errno_t
img4_nonce_domain_preroll_nonce(const img4_nonce_domain_t *nd, img4_nonce_t *n);
#else
#define img4_nonce_domain_preroll_nonce(...) \
		(img4if->i4if_v14.nonce_domain_preroll_nonce(__VA_ARGS__))
#endif

#endif // __IMG4_NONCE_H
STAGEEOF
    echo "Staged img4/nonce.h (no KDK)"
fi
if [ ! -f "EXTERNAL_HEADERS/img4/object.h" ]; then
    mkdir -p "EXTERNAL_HEADERS/img4"
    cat > "EXTERNAL_HEADERS/img4/object.h" <<'STAGEEOF'
/*!
 * @header
 * Image4 object specifications.
 */
#ifndef __IMG4_OBJECT_H
#define __IMG4_OBJECT_H

#ifndef __IMG4_INDIRECT
#error "Please #include <img4/firmware.h> instead of this file directly"
#endif // __IMG4_INDIRECT

OS_ASSUME_NONNULL_BEGIN

/*!
 * @typedef img4_object_spec_t
 * An opaque type which describes information about Image4 objects for use by
 * the runtime.
 */
IMG4_API_AVAILABLE_20200508
typedef struct _img4_object_spec img4_object_spec_t;

/*!
 * @const IMG4_FIRMWARE_SPEC
 * The object specification for an {@link img4_firmware_t} object.
 */
#if !XNU_KERNEL_PRIVATE
IMG4_API_AVAILABLE_20200508
OS_EXPORT
const img4_object_spec_t _img4_firmware_spec;
#define IMG4_FIRMWARE_SPEC (&_img4_firmware_spec)
#else
#define IMG4_FIRMWARE_SPEC (img4if->i4if_v7.firmware_spec)
#endif

/*!
 * @const IMG4_FIRMWARE_SIZE_RECOMMENDED
 * A constant describing the recommended stack allocation required for a
 * {@link img4_firmware_t} object.
 */
#define IMG4_FIRMWARE_SIZE_RECOMMENDED (1280u)

/*!
 * @const IMG4_CHIP_SPEC
 * The object specification for an {@link img4_chip_t} object.
 */
#if !XNU_KERNEL_PRIVATE
IMG4_API_AVAILABLE_20200508
OS_EXPORT
const img4_object_spec_t _img4_chip_spec;
#define IMG4_CHIP_SPEC (&_img4_chip_spec)
#else
#define IMG4_CHIP_SPEC (img4if->i4if_v7.chip_spec)
#endif

/*!
 * @const IMG4_CHIP_SIZE_RECOMMENDED
 * A constant describing the recommended stack allocation required for a
 * {@link img4_chip_t} object.
 */
#define IMG4_CHIP_SIZE_RECOMMENDED (384u)

/*!
 * @const IMG4_PMAP_DATA_SPEC
 * The object specification for an {@link img4_pmap_data_t} object.
 */
#if !XNU_KERNEL_PRIVATE
IMG4_API_AVAILABLE_20210521
OS_EXPORT
const img4_object_spec_t _img4_pmap_data_spec;
#define IMG4_PMAP_DATA_SPEC (&_img4_pmap_data_spec)
#else
#define IMG4_PMAP_DATA_SPEC (img4if->i4if_v13.pmap_data_spec)
#endif

/*!
 * @const IMG4_CHIP_SIZE_RECOMMENDED
 * A constant describing the recommended stack allocation required for a
 * {@link img4_pmap_data_t} object.
 */
#define IMG4_PMAP_DATA_SIZE_RECOMMENDED (2048u)

OS_ASSUME_NONNULL_END

#endif // __IMG4_OBJECT_H
STAGEEOF
    echo "Staged img4/object.h (no KDK)"
fi
if [ ! -f "EXTERNAL_HEADERS/img4/runtime.h" ]; then
    mkdir -p "EXTERNAL_HEADERS/img4"
    cat > "EXTERNAL_HEADERS/img4/runtime.h" <<'STAGEEOF'
/*!
 * @header
 * Image4 runtime interfaces.
 */
#ifndef __IMG4_RUNTIME_H
#define __IMG4_RUNTIME_H

#ifndef __IMG4_INDIRECT
#error "Please #include <img4/firmware.h> instead of this file directly"
#endif // __IMG4_INDIRECT

OS_ASSUME_NONNULL_BEGIN

/*!
 * @typedef img4_identifier_t
 * An enumeration describing identifiers in the Image4 specification.
 *
 * @const IMG4_IDENTIFIER_CEPO
 * The chip epoch as documented in 2.1.1. Authoritative manifests will specify a
 * certificate epoch which is greater than or equal to that of the chip.
 *
 * Unsigned 32-bit integer.
 *
 * @const IMG4_IDENTIFIER_BORD
 * The board identifier as documented in 2.1.3. Authoritative manifests will
 * specify a board identifier which is equal to that of the chip.
 *
 * Unsigned 32-bit integer.
 *
 * @const IMG4_IDENTIFIER_CHIP
 * The chip identifier as documented in 2.1.2. Authoritative manifests will
 * specify a chip identifier which is equal to that of the chip.
 *
 * Unsigned 32-bit integer.
 *
 * @const IMG4_IDENTIFIER_SDOM
 * The security domain as documented in 2.1.5. Authoritative manifests will
 * specify a security domain which is equal to that that of the chip.
 *
 * Unsigned 32-bit integer. Valid values are
 *
 *     0    Manufacturing
 *     1    Darwin
 *     2    Data Center (unsure)
 *     3    Unused
 *
 * @const IMG4_IDENTIFIER_ECID
 * The unique chip identifier as documented in 2.1.4. Authoritative manifests
 * will specify a unique chip identifier which is equal to that of the chip.
 *
 * Unsigned 64-bit integer.
 *
 * @const IMG4_IDENTIFIER_CPRO
 * The certificate production status as documented in 2.1.6. Authoritative
 * manifests will specify a certificate production status which is equal to that
 * of the chip.
 *
 * Boolean.
 *
 * @const IMG4_IDENTIFIER_CSEC
 * The certificate security mode as documented in 2.1.7. Authoritative manifests
 * will specify a certificate security mode which is equal to that of the chip.
 *
 * Boolean.
 *
 * @const IMG4_IDENTIFIER_EPRO
 * The effective production status as documented in 2.1.23. Unless the chip
 * environment supports demotion, this will always be the same as
 * {@link IMG4_IDENTIFIER_CPRO}. An executable firmware in an authoritative
 * manifest will specify an EPRO object property which is equal to that of the
 * chip post-demotion.
 *
 * Boolean.
 *
 * @const IMG4_IDENTIFIER_ESEC
 * The effective security mode as documented in 2.1.25. Unless the chip
 * environment supports demotion, this will always be the same as
 * {@link IMG4_IDENTIFIER_CSEC}. An executable firmware in an authoritative
 * manifest will specify an ESEC object property which is equal to that of the
 * chip post-demotion.
 *
 * Boolean.
 *
 * @const IMG4_IDENTIFIER_IUOU
 * The "internal use only unit" property. Indicates whether the chip is present
 * on a server-side authlist which permits installing builds which are otherwise
 * restricted to parts whose CPRO is 0. This property is only published by macOS
 * devices whose root of trust is in an arm coprocessor (e.g. T2).
 *
 * Authoritative manifests will specify an internal-use-only-build property
 * which, if true, is equal to the internal-use-only-unit property of the chip.
 * If the internal-use-only-build property is false, then there is no constraint
 * on the chip's internal-use-only-unit property.
 *
 * Boolean.
 *
 * @const IMG4_IDENTIFIER_RSCH
 * The research fusing status. Indicates whether the chip is intended for
 * security research to be performed by external parties. Authoritative
 * manifests will specify a research fusing state which is equal to that of the
 * chip.
 *
 * Boolean.
 *
 * This identifier was never recognized by SecureROM and has been obsoleted by
 * {@link IMG4_IDENTIFIER_ESDM}.
 *
 * @const IMG4_IDENTIFIER_CHMH
 * The chained manifest hash from the previous stage of secure boot as described
 * in 2.2.11. An authoritative manifest will either
 *
 *     - specify a manifest hash which is equal to that of the previous secure
 *       boot stage's manifest
 *     - itself have a manifest hash which is equal to that of the previous
 *       secure boot stage's manifest
 *
 * If the previous stage of secure boot enabled mix-n-match, there is no
 * constraint on the previous stage's manifest hash.
 *
 * Manifests which specify this property cannot be used to create new trust
 * chains -- they may only extend existing ones.
 *
 * Digest.
 *
 * @const IMG4_IDENTIFIER_AMNM
 * The allow-mix-n-match status of the chip. If mix-n-match is enabled, secure
 * boot will permit different manifests to be used at each stage of boot. If the
 * chip environment allows mix-n-match, evaluation will not require an anti-
 * replay token to be specified, and any chained manifest hash constraints are
 * ignored.
 *
 * Boolean.
 *
 * @const IMG4_IDENTIFIER_EUOU
 * The engineering-use-only-unit status of the chip. This is in effect an alias
 * for the {@link IMG4_IDENTIFIER_IUOU} property. Either property being present
 * in the environment will satisfy a manifest's iuob constraint.
 *
 * Boolean.
 *
 * @const IMG4_IDENTIFIER_LOVE
 * The long version of the OS currently booted on the chip (Long Os VErsion).
 *
 * Authoritative manifests will specify a version number which is greater than
 * that of the chip.
 *
 * C string.
 *
 * @const IMG4_IDENTIFIER_ESDM
 * The extended security domain of the chip. Authoritative manifests will
 * specify an extended security domain which is equal to that of the chip.
 *
 * Unsigned 32-bit integer. This integer represents 8 fusing bits, and therefore
 * the maximum valid value is 0xff.
 *
 * @const IMG4_IDENTIFIER_FPGT
 * The factory pre-release global trust status of the chip. This is in effect an
 * alias for the {@link IMG4_IDENTIFIER_IUOU} property. Either property being
 * present in the environment will satisfy a manifest's iuob constraint.
 *
 * Boolean.
 *
 * @const IMG4_IDENTIFIER_UDID
 * The universal device identifier of the chip. This uniquely identifies the SoC
 * globally across all SoCs. Authoritative manifests will specify a UDID which
 * is equal to that of the chip.
 *
 * 128-bit octet string.
 *
 * @const IMG4_IDENTIFIER_FCHP
 * The chip identifier of the Cryptex coprocessor associated with the chip. This
 * distinguishes the software Crytpex coprocessor instances which operate on the
 * AP. Authoritative manifests will specify a Cryptex chip identifier that is
 * equal to that of the chip.
 *
 * Runtimes are not capable of reporting this value, and queries for it should
 * return ENOENT. This invariant is defined for convenience to the
 * implementation.
 *
 * Unsigned 32-bit integer.
 *
 * @const IMG4_IDENTIFIER_TYPE
 * The type identifier of the Cryptex coprocessor associated with the chip. This
 * distinguishes software Cryptex coprocessor instances of the same chip
 * identifier which operate on the AP. Authoritative manifests will specify a
 * Cryptex type that is equal to that of the chip.
 *
 * Runtimes are not capable of reporting this value, and queries for it should
 * return ENOENT. This invariant is defined for convenience to the
 * implementation.
 *
 * Unsigned 32-bit integer.
 *
 * @const IMG4_IDENTIFIER_STYP
 * The subtype identifier of the Cryptex coprocessor associated with the chip.
 * This permits an additional level of granularity to distinguish Cryptex
 * coprocessor instances from one another. Authoritative manifests will specify
 * a Cryptex subtype that is equal to that of the chip.
 *
 * Runtimes are not capable of reporting this value, and queries for it should
 * return ENOENT. This invariant is defined for convenience to the
 * implementation.
 *
 * Unsigned 32-bit integer.
 *
 * @const IMG4_IDENTIFIER_CLAS
 * The product class of the Cryptex coprocessor associated with the chip.
 * Authoritative manifests will specify a product class that is equal to that of
 * the chip.
 *
 * Valid values for this property are:
 *
 *     0xf0 - Intel Mac (with or without T2 security chip)
 *     0xf1 - Apple Silicon Mac
 *     0xf2 - iPhone/iPad/iPod touch
 *     0xf3 - watch
 *     0xf4 - tv/HomePod
 *
 * Unsigned 32-bit integer.
 *
 * @const IMG4_IDENTIFIER_SPIH
 * The booted supplemental manifest hash.
 *
 * Digest.
 *
 * @const IMG4_IDENTIFIER_NSPH
 * The preboot supplemental manifest hash intended to become active at the next
 * boot.
 *
 * Digest.
 *
 * @const IMG4_IDENTIFIER_STNG
 * The generation number of the last-executed blessed local policy on the AP.
 *
 * Unsigned 64-bit integer.
 *
 * @const IMG4_IDENTIFIER_VUID
 * The volume group UUID that the chip is booting from.
 *
 * 128-bit octet string.
 *
 * @const _IMG4_IDENTIFIER_CNT
 * A convenience value representing the number of known identifiers.
 */
IMG4_API_AVAILABLE_20200508
OS_CLOSED_ENUM(img4_identifier, uint64_t,
	IMG4_IDENTIFIER_CEPO,
	IMG4_IDENTIFIER_BORD,
	IMG4_IDENTIFIER_CHIP,
	IMG4_IDENTIFIER_SDOM,
	IMG4_IDENTIFIER_ECID,
	IMG4_IDENTIFIER_CPRO,
	IMG4_IDENTIFIER_CSEC,
	IMG4_IDENTIFIER_EPRO,
	IMG4_IDENTIFIER_ESEC,
	IMG4_IDENTIFIER_IUOU,
	IMG4_IDENTIFIER_RSCH,
	IMG4_IDENTIFIER_CHMH,
	IMG4_IDENTIFIER_AMNM,
	IMG4_IDENTIFIER_EUOU,
	IMG4_IDENTIFIER_LOVE,
	IMG4_IDENTIFIER_ESDM,
	IMG4_IDENTIFIER_FPGT,
	IMG4_IDENTIFIER_UDID,
	IMG4_IDENTIFIER_FCHP,
	IMG4_IDENTIFIER_TYPE,
	IMG4_IDENTIFIER_STYP,
	IMG4_IDENTIFIER_CLAS,
	IMG4_IDENTIFIER_SPIH,
	IMG4_IDENTIFIER_NSPH,
	IMG4_IDENTIFIER_STNG,
	IMG4_IDENTIFIER_VUID,
	_IMG4_IDENTIFIER_CNT,
);

/*!
 * @typedef img4_pmap_data_t
 * An opaque type representing state protected by the host's page mapping layer
 * as it deems appropriate. Do not use directly.
 */
IMG4_API_AVAILABLE_20210521
typedef struct _img4_pmap_data img4_pmap_data_t;

/*!
 * @typedef img4_runtime_object_spec_index_t
 * An enumeration describing the executable objects recognized by runtimes.
 *
 * @const IMG4_RUNTIME_OBJECT_SPEC_INDEX_MANIFEST
 * The enumerated constant which refers to the internal manifest object.
 *
 * @const IMG4_RUNTIME_OBJECT_SPEC_INDEX_SUPPLEMENTAL_ROOT
 * The enumerated constant which refers to the
 * {@link IMG4_RUNTIME_OBJECT_SPEC_SUPPLEMENTAL_ROOT} object.
 *
 * @const IMG4_RUNTIME_OBJECT_SPEC_INDEX_SUPPLEMENTAL_OBJECT
 * The enumerated constant which refers to the
 * {@link IMG4_RUNTIME_OBJECT_SPEC_SUPPLEMENTAL_OBJECT} object.
 *
 * @const IMG4_RUNTIME_OBJECT_SPEC_INDEX_LOCAL_POLICY
 * The enumerated constant which refers to the
 * {@link IMG4_RUNTIME_OBJECT_SPEC_LOCAL_POLICY} object.
 *
 * @const _IMG4_RUNTIME_OBJECT_SPEC_INDEX_CNT
 * A sentinel value representing the total number of executable object
 * specifications.
 */
IMG4_API_AVAILABLE_20210521
OS_CLOSED_ENUM(img4_runtime_object_spec_index, uint64_t,
	IMG4_RUNTIME_OBJECT_SPEC_INDEX_MANIFEST,
	IMG4_RUNTIME_OBJECT_SPEC_INDEX_SUPPLEMENTAL_ROOT,
	IMG4_RUNTIME_OBJECT_SPEC_INDEX_SUPPLEMENTAL_OBJECT,
	IMG4_RUNTIME_OBJECT_SPEC_INDEX_LOCAL_POLICY,
	_IMG4_RUNTIME_OBJECT_SPEC_INDEX_CNT,
);

/*!
 * @typedef img4_runtime_object_spec_t
 * A specification for an object known to and executable by a runtime.
 */
IMG4_API_AVAILABLE_20210205
typedef struct _img4_runtime_object_spec img4_runtime_object_spec_t;

/*!
 * @typedef img4_runtime_init_t
 * A function which initializes the runtime.
 *
 * @param rt
 * The runtime for which the function is being invoked.
 *
 * @discussion
 * This function is called by the implementation prior to any other runtime
 * function being called. The implementation will ensure that it is called only
 * once. Any runtime with an initialization function must be registered with the
 * {@link IMG4_RUNTIME_REGISTER} macro.
 */
IMG4_API_AVAILABLE_20200508
typedef void (*img4_runtime_init_t)(
	const img4_runtime_t *rt
);

/*!
 * @typedef img4_runtime_alloc_t
 * An allocation function.
 *
 * @param rt
 * The runtime for which the function is being invoked.
 *
 * @param n
 * The number of bytes to allocate.
 *
 * @result
 * A pointer to the new allocation, or NULL if there was an allocation failure.
 *
 * The memory returned by this function is expected to be zero-filled.
 */
IMG4_API_AVAILABLE_20200508
typedef void *_Nullable (*img4_runtime_alloc_t)(
	const img4_runtime_t *rt,
	size_t n
);

/*!
 * @typedef img4_runtime_dealloc_t
 * A deallocation function.
 *
 * @param rt
 * The runtime for which the function is being invoked.
 *
 * @param p
 * A pointer to the allocation to free. The callee is expected to return
 * immediately if NULL is passed.
 *
 * @param n
 * The size of the allocation. Not all implementation may require this
 * information to be specified.
 */
IMG4_API_AVAILABLE_20200508
typedef void (*img4_runtime_dealloc_t)(
	const img4_runtime_t *rt,
	void *_Nullable p,
	size_t n
);

/*!
 * @typedef img4_log_level_t
 * An enumeration describing the importance/severity of a log message.
 *
 * @const IMG4_LOG_LEVEL_ERROR
 * A fatal condition which will cause the implementation to abort its current
 * operation.
 *
 * @const IMG4_LOG_LEVEL_INFO
 * Information that may be of interest to the system operator.
 *
 * @const IMG4_LOG_LEVEL_DEBUG
 * Information that may be of interest to the maintainer.
 *
 * @const _IMG4_LOG_LEVEL_CNT
 * A convenience constant indicating the number of log levels.
 */
IMG4_API_AVAILABLE_20200508
OS_CLOSED_ENUM(img4_log_level, uint64_t,
	IMG4_LOG_LEVEL_ERROR,
	IMG4_LOG_LEVEL_INFO,
	IMG4_LOG_LEVEL_DEBUG,
	_IMG4_LOG_LEVEL_CNT,
);

/*!
 * @typedef img4_runtime_log_t
 * A function which writes log messages.
 *
 * @param rt
 * The runtime for which the function is being invoked.
 *
 * @param handle
 * An implementation-specific handle for the log message.
 *
 * @param level
 * The message of the log level. The implementation is free to determine whether
 * a given message is worthy of record.
 *
 * @param fmt
 * A printf(3)-style format string.
 *
 * @param ...
 * Arguments to be interpreted by the format string according to the
 * specifications in printf(3).
 */
OS_FORMAT_PRINTF(4, 5)
IMG4_API_AVAILABLE_20200508
typedef void (*img4_runtime_log_t)(
	const img4_runtime_t *rt,
	void *_Nullable handle,
	img4_log_level_t level,
	const char *fmt,
	...
);

/*!
 * @typedef img4_runtime_log_handle_t
 * A function which returns a log handle.
 *
 * @param rt
 * The runtime for which the function is being invoked.
 *
 * @result
 * A runtime-specific log handle that will be passed to the logging function.
 */
IMG4_API_AVAILABLE_20200508
typedef void *_Nullable (*img4_runtime_log_handle_t)(
	const img4_runtime_t *rt
);

/*!
 * @typedef img4_runtime_get_identifier_bool_t
 * A function which retrieves a Boolean Image4 identifier.
 *
 * @param rt
 * The runtime for which the function is being invoked.
 *
 * @param chip
 * The chip for which to retrieve the identifier.
 *
 * @param identifier
 * The identifier to retrieve.
 *
 * @param value
 * Upon successful return, storage which is populated with the retrieved value.
 *
 * @result
 * Upon success, the callee is expected to return zero. Otherwise, the callee
 * may return one of the following error codes:
 *
 *     [ENOTSUP]     The identifier cannot be queried in the runtime
 *     [ENOENT]      The identifier was not found in the runtime's identity
 *                   oracle
 *     [ENODEV]      There was an error querying the runtime's identity oracle
 */
IMG4_API_AVAILABLE_20200508
typedef errno_t (*img4_runtime_get_identifier_bool_t)(
	const img4_runtime_t *rt,
	const img4_chip_t *chip,
	img4_identifier_t identifier,
	bool *value
);

/*!
 * @typedef img4_runtime_get_identifier_uint32_t
 * A function which retrieves an unsigned 32-bit integer Image4 identifier.
 *
 * @param rt
 * The runtime for which the function is being invoked.
 *
 * @param chip
 * The chip for which to retrieve the identifier.
 *
 * @param identifier
 * The identifier to retrieve.
 *
 * @param value
 * Upon successful return, storage which is populated with the retrieved value.
 *
 * @result
 * Upon success, the callee is expected to return zero. Otherwise, the callee
 * may return one of the following error codes:
 *
 *     [ENOTSUP]     The identifier cannot be queried in the runtime
 *     [ENOENT]      The identifier was not found in the runtime's identity
 *                   oracle
 *     [ENODEV]      There was an error querying the runtime's identity oracle
 */
IMG4_API_AVAILABLE_20200508
typedef errno_t (*img4_runtime_get_identifier_uint32_t)(
	const img4_runtime_t *rt,
	const img4_chip_t *chip,
	img4_identifier_t identifier,
	uint32_t *value
);

/*!
 * @typedef img4_runtime_get_identifier_uint64_t
 * A function which retrieves an unsigned 64-bit integer Image4 identifier.
 *
 * @param rt
 * The runtime for which the function is being invoked.
 *
 * @param chip
 * The chip for which to retrieve the identifier.
 *
 * @param identifier
 * The identifier to retrieve.
 *
 * @param value
 * Upon successful return, storage which is populated with the retrieved value.
 *
 * @result
 * Upon success, the callee is expected to return zero. Otherwise, the callee
 * may return one of the following error codes:
 *
 *     [ENOTSUP]     The identifier cannot be queried in the runtime
 *     [ENOENT]      The identifier was not found in the runtime's identity
 *                   oracle
 *     [ENODEV]      There was an error querying the runtime's identity oracle
 */
IMG4_API_AVAILABLE_20200508
typedef errno_t (*img4_runtime_get_identifier_uint64_t)(
	const img4_runtime_t *rt,
	const img4_chip_t *chip,
	img4_identifier_t identifier,
	uint64_t *value
);

/*!
 * @typedef img4_runtime_get_identifier_digest_t
 * A function which retrieves a digest Image4 identifier.
 *
 * @param rt
 * The runtime for which the function is being invoked.
 *
 * @param chip
 * The chip for which to retrieve the identifier.
 *
 * @param identifier
 * The identifier to retrieve.
 *
 * @param value
 * Upon successful return, storage which is populated with the retrieved value.
 *
 * @result
 * Upon success, the callee is expected to return zero. Otherwise, the callee
 * may return one of the following error codes:
 *
 *     [ENOTSUP]     The identifier cannot be queried in the runtime
 *     [ENOENT]      The identifier was not found in the runtime's identity
 *                   oracle
 *     [ENODEV]      There was an error querying the runtime's identity oracle
 */
IMG4_API_AVAILABLE_20200508
typedef errno_t (*img4_runtime_get_identifier_digest_t)(
	const img4_runtime_t *rt,
	const img4_chip_t *chip,
	img4_identifier_t identifier,
	img4_dgst_t *value
);

/*!
 * @typedef img4_runtime_get_identifier_cstr_t
 * A function which retrieves a C-string Image4 identifier.
 *
 * @param rt
 * The runtime for which the function is being invoked.
 *
 * @param chip
 * The chip for which to retrieve the identifier.
 *
 * @param identifier
 * The identifier to retrieve.
 *
 * @param value
 * Upon successful return, storage which is populated with the retrieved value.
 *
 * @result
 * Upon success, the callee is expected to return zero. Otherwise, the callee
 * may return one of the following error codes:
 *
 *     [ENOTSUP]     The identifier cannot be queried in the runtime
 *     [ENOENT]      The identifier was not found in the runtime's identity
 *                   oracle
 *     [ENODEV]      There was an error querying the runtime's identity oracle
 */
IMG4_API_AVAILABLE_20210113
typedef errno_t (*img4_runtime_get_identifier_cstr_t)(
	const img4_runtime_t *rt,
	const img4_chip_t *chip,
	img4_identifier_t identifier,
	img4_cstr_t *value
);

/*!
 * @typedef img4_runtime_execute_object_t
 * A function which executes an object type known to the runtime.
 *
 * @param rt
 * The runtime for which the function is being invoked.
 *
 * @param obj_spec
 * The object specification for the payload being executed.
 *
 * @param payload
 * The payload bytes to execute. These bytes are delivered in their raw form,
 * i.e. without any Image4 payload wrapping.
 *
 * @param manifest
 * The manifest which authenticats the payload. If the payload is intended to be
 * used without authentication (or with alternate means of authentication), this
 * may be NULL.
 *
 * @result
 * Upon success, the callee is expected to return zero. Otherwise, the callee
 * may return any appropriate POSIX error code.
 *
 * @discussion
 * This function is only called if the payload has been successfully
 * authenticated; the callee can consider the bytes as trusted.
 */
IMG4_API_AVAILABLE_20210205
typedef errno_t (*img4_runtime_execute_object_t)(
	const img4_runtime_t *rt,
	const img4_runtime_object_spec_t *obj_spec,
	const img4_buff_t *payload,
	const img4_buff_t *_Nullable manifest
);

/*!
 * @typedef img4_runtime_copy_object_t
 * A function which obtains the payload of a previously-executed object.
 *
 * @param rt
 * The runtime for which the function is being invoked.
 *
 * @param obj_spec
 * The object specification for the payload being obtained.
 *
 * @param payload
 * A pointer to a buffer object in which to copy the object.
 *
 * @param payload_len
 * Upon successful return, a pointer to the total number of bytes coped into the
 * buffer referred to by {@link payload}. This parameter may be NULL.
 *
 * In the event that buffer referred to be {@link payload} is insufficient to,
 * accommodate the object, the callee is expected to set this parameter to the
 * total number of bytes required.
 *
 * @result
 * Upon success, the callee is expected to return zero. Otherwise, the callee
 * may return one of the following error codes:
 *
 *     [EOVERFLOW]     The provided buffer is not large enough for the payload;
 *                     in this case the callee is expected to set the
 *                     {@link i4b_len} of the given buffer to the required
 *                     length
 *     [ENOENT]        The object has not yet been executed
 */
IMG4_API_AVAILABLE_20210205
typedef errno_t (*img4_runtime_copy_object_t)(
	const img4_runtime_t *rt,
	const img4_runtime_object_spec_t *obj_spec,
	img4_buff_t *payload,
	size_t *_Nullable payload_len
);

/*!
 * @typedef img4_runtime_alloc_type_t
 * A function which allocates a single object of a given type.
 *
 * @param rt
 * The runtime for which the function is being invoked.
 *
 * @param handle
 * The domain-specific handle describing the object and the allocation site.
 *
 * @result
 * A pointer to the new allocation, or NULL if there was an allocation failure.
 * The memory returned by this function is expected to be zero-filled.
 */
IMG4_API_AVAILABLE_20210226
typedef void *_Nullable (*img4_runtime_alloc_type_t)(
	const img4_runtime_t *rt,
	void *_Nullable handle
);

/*!
 * @typedef img4_runtime_dealloc_type_t
 * A function which deallocates a single object of a given type.
 *
 * @param rt
 * The runtime for which the function is being invoked.
 *
 * @param handle
 * The domain-specific handle describing the object and the deallocation site.
 *
 * @param p
 * The address of the object to deallocate.
 */
IMG4_API_AVAILABLE_20210226
typedef void (*img4_runtime_dealloc_type_t)(
	const img4_runtime_t *rt,
	void *_Nullable handle,
	void *p
);

/*!
 * @typedef img4_runtime_set_nonce_t
 * A function which sets the value of a nonce managed by the runtime.
 *
 * @param rt
 * The runtime for which the function is being invoked.
 *
 * @param ndi
 * The index of the nonce domain whose nonce should be set.
 *
 * @param n
 * The value of the nonce indicated by {@link nd}.
 */
IMG4_API_AVAILABLE_20210521
typedef void (*img4_runtime_set_nonce_t)(
	const img4_runtime_t *rt,
	img4_nonce_domain_index_t ndi,
	const img4_nonce_t *n
);

/*!
 * @typedef img4_runtime_roll_nonce_t
 * A function which rolls a nonce managed by the runtime.
 *
 * @param rt
 * The runtime for which the function is being invoked.
 *
 * @param ndi
 * The index of the nonce domain whose nonce should be rolled.
 */
IMG4_API_AVAILABLE_20210521
typedef void (*img4_runtime_roll_nonce_t)(
	const img4_runtime_t *rt,
	img4_nonce_domain_index_t ndi
);

/*!
 * @typedef img4_runtime_copy_nonce_t
 * A function which retrieve the value of a nonce managed by the runtime.
 *
 * @param rt
 * The runtime for which the function is being invoked.
 *
 * @param ndi
 * The index of the nonce domain whose nonce should be queried.
 *
 * @param n
 * Upon successful return, the value of the nonce indicated by {@link nd}. If
 * the caller simply wishes to check if the nonce has been invalidated, this
 * parameter may be NULL, and the caller can check for ESTALE.
 *
 * @result
 * Upon success, zero is returned. The implementation may also return one of the
 * following error codes directly:
 *
 *     [ESTALE]     The nonce for the given domain has been invalidated, and the
 *                  host must reboot in order to generate a new one
 */
IMG4_API_AVAILABLE_20210521
typedef errno_t (*img4_runtime_copy_nonce_t)(
	const img4_runtime_t *rt,
	img4_nonce_domain_index_t ndi,
	img4_nonce_t *_Nullable n
);

/*!
 * @define IMG4_BUFF_STRUCT_VERSION
 * The version of the {@link img4_buff_t} structure supported by the
 * implementation.
 */
#define IMG4_BUFF_STRUCT_VERSION (0u)

/*!
 * @struct _img4_buff
 * A structure describing a buffer.
 *
 * @field i4b_version
 * The version of the structure. Initialize to {@link IMG4_BUFF_STRUCT_VERSION}.
 *
 * @field i4b_bytes
 * A pointer to the buffer.
 *
 * @field i4b_len
 * The length of the buffer.
 *
 * @field i4b_dealloc
 * The deallocation function for the buffer. May be NULL if the underlying
 * memory does not require cleanup. When the implementation invokes this
 * function, it will always pass {@link IMG4_RUNTIME_DEFAULT}, and the callee
 * should not consult this parameter for any reason.
 */
struct _img4_buff {
	img4_struct_version_t i4b_version;
	uint8_t *i4b_bytes;
	size_t i4b_len;
	img4_runtime_dealloc_t _Nullable i4b_dealloc;
} IMG4_API_AVAILABLE_20200508;

/*!
 * @const IMG4_BUFF_INIT
 * A convenience initializer for the {@link img4_buff_t} structure.
 */
#if defined(__STDC_VERSION__) && __STDC_VERSION__ >= 199901L
#define IMG4_BUFF_INIT (img4_buff_t){ \
	.i4b_version = IMG4_BUFF_STRUCT_VERSION, \
	.i4b_len = 0, \
	.i4b_bytes = NULL, \
	.i4b_dealloc = NULL, \
}
#elif defined(__cplusplus) && __cplusplus >= 201103L
#define IMG4_BUFF_INIT (img4_buff_t{ \
	IMG4_BUFF_STRUCT_VERSION, \
	NULL, \
	0, \
	NULL, \
})
#elif defined(__cplusplus)
#define IMG4_BUFF_INIT (img4_buff_t((img4_buff_t){ \
	IMG4_BUFF_STRUCT_VERSION, \
	NULL, \
	0, \
	NULL, \
}))
#else
#define IMG4_BUFF_INIT {IMG4_BUFF_STRUCT_VERSION}
#endif

/*!
 * @define IMG4_RUNTIME_STRUCT_VERSION
 * The version of the {@link img4_runtime_t} structure supported by the
 * implementation.
 */
#define IMG4_RUNTIME_STRUCT_VERSION (5u)

/*!
 * @struct _img4_runtime
 * A structure describing required primitives in the operating environment's
 * runtime.
 *
 * @field i4rt_version
 * The version of the structure supported by the implementation. In a custom
 * execution context, initialize to {@link IMG4_RUNTIME_STRUCT_VERSION}.
 *
 * @field i4rt_name
 * A string describing the environment.
 *
 * @field i4rt_init
 * The runtime initialization function. See discussion in
 * {@link img4_runtime_init_t}.
 *
 * @field i4rt_alloc
 * The allocation function for the environment (e.g. in Darwin userspace, this
 * would be a pointer to malloc(3)). The memory returned is expected to be zero-
 * filled.
 *
 * @field i4rt_dealloc
 * The deallocation function for the environment (e.g. in Darwin userspace, this
 * would be a pointer to free(3)).
 *
 * @field i4rt_log
 * The function which logs messages from the implementation.
 *
 * @field i4rt_log_handle
 * The function which returns the handle to be passed to the logging function.
 *
 * @field i4rt_get_identifier_bool
 * The function which returns Boolean identifiers.
 *
 * @field i4rt_get_identifier_uint32
 * The function which returns unsigned 32-bit integer identifiers.
 *
 * @field i4rt_get_identifier_uint64
 * The function which returns unsigned 64-bit integer identifiers.
 *
 * @field i4rt_get_identifier_digest
 * The function which returns digest identifiers.
 *
 * @field i4rt_context
 * A user-defined context pointer. Introduced in version 1 of the structure.
 *
 * @field i4rt_get_identifier_cstr
 * The function which returns C-string identifiers. Introduced in version 2 of
 * the structure.
 *
 * @field i4rt_execute_object
 * The function which executes objects. Introduced in version 3 of the
 * structure.
 *
 * @field i4rt_copy_object
 * The function which copies objects. Introduced in version 3 of the structure.
 *
 * @field i4rt_alloc_type
 * The typed allocation function for the environment. This allocator should be
 * used for any fixed-size, structured allocation that may contain pointers.
 *
 * The memory returned is expected to be zero-filled. Introduced in version 4 of
 * the structure.
 *
 * @field i4rt_dealloc_type
 * The typed deallocation function for the environment. Introduced in version 4
 * of the structure.
 *
 * @field i4rt_set_nonce
 * The nonce-set function for the environment. Introduced in version 5 of the
 * structure.
 *
 * @field i4rt_roll_nonce
 * The nonce-roll function for the environment. Introduced in version 5 of the
 * structure.
 *
 * @field i4rt_roll_nonce
 * The nonce-copy function for the environment. Introduced in version 5 of the
 * structure.
 */
struct _img4_runtime {
	img4_struct_version_t i4rt_version;
	const char *i4rt_name;
	img4_runtime_init_t _Nullable i4rt_init;
	img4_runtime_alloc_t i4rt_alloc;
	img4_runtime_dealloc_t i4rt_dealloc;
	img4_runtime_log_t i4rt_log;
	img4_runtime_log_handle_t i4rt_log_handle;
	img4_runtime_get_identifier_bool_t i4rt_get_identifier_bool;
	img4_runtime_get_identifier_uint32_t i4rt_get_identifier_uint32;
	img4_runtime_get_identifier_uint64_t i4rt_get_identifier_uint64;
	img4_runtime_get_identifier_digest_t i4rt_get_identifier_digest;
	void *_Nullable i4rt_context;
	img4_runtime_get_identifier_cstr_t i4rt_get_identifier_cstr;
	img4_runtime_execute_object_t i4rt_execute_object;
	img4_runtime_copy_object_t i4rt_copy_object;
	img4_runtime_alloc_type_t i4rt_alloc_type;
	img4_runtime_dealloc_type_t i4rt_dealloc_type;
	img4_runtime_set_nonce_t i4rt_set_nonce;
	img4_runtime_roll_nonce_t i4rt_roll_nonce;
	img4_runtime_copy_nonce_t i4rt_copy_nonce;
} IMG4_API_AVAILABLE_20200508;

/*!
 * @function IMG4_RUNTIME_REGISTER
 * Registers a runtime with the module implementation such that its
 * initialization function can be called. In environments which support dynamic
 * library linkage, only runtimes registered from the main executable image can
 * be discovered by the implementation.
 *
 * @param _rt
 * The img4_runtime_t structure to register.
 */
#define IMG4_RUNTIME_REGISTER(_rt) LINKER_SET_ENTRY(__img4_rt, _rt);

/*!
 * @const IMG4_RUNTIME_DEFAULT
 * The default runtime for the current operating environment.
 */
#if !XNU_KERNEL_PRIVATE
IMG4_API_AVAILABLE_20200508
OS_EXPORT
const img4_runtime_t _img4_runtime_default;
#define IMG4_RUNTIME_DEFAULT (&_img4_runtime_default)
#else
#define IMG4_RUNTIME_DEFAULT (img4if->i4if_v7.runtime_default)
#endif

/*!
 * @const IMG4_RUNTIME_PMAP_CS
 * The runtime for the xnu pmap layer which is safe to be executed in a
 * supervisor execution level if supported by hardware. This runtime is not
 * available outside the kernel-proper.
 */
#if XNU_KERNEL_PRIVATE
#define IMG4_RUNTIME_PMAP_CS (img4if->i4if_v7.runtime_pmap_cs)
#elif _DARWIN_BUILDING_TARGET_APPLEIMAGE4
#define IMG4_RUNTIME_PMAP_CS (&_img4_runtime_pmap_cs)
#endif

/*!
 * @const IMG4_RUNTIME_RESTORE
 * The runtime for the restore ramdisk. This runtime is not available outside
 * of the Darwin userspace library.
 */
#if !KERNEL
IMG4_API_AVAILABLE_20200508
OS_EXPORT
const img4_runtime_t _img4_runtime_restore;
#define IMG4_RUNTIME_RESTORE (&_img4_runtime_restore)
#endif

/*!
 * @function img4_buff_dealloc
 * Deallocates a buffer according to its deallocation function.
 *
 * @param buff
 * A pointer to the a pointer to the buffer. This parameter may be NULL, in
 * which case the implementation will return immediately.
 *
 * @discussion
 * This interface will always invoke the deallocation callback with
 * {@link IMG4_RUNTIME_DEFAULT}. The callee should not consult this parameter
 * for any reason.
 */
#if !XNU_KERNEL_PRIVATE
IMG4_API_AVAILABLE_20200508
OS_EXPORT
void
img4_buff_dealloc(img4_buff_t *_Nullable buff);
#else
#define img4_buff_dealloc(...) (img4if->i4if_v7.buff_dealloc(__VA_ARGS__))
#endif

#pragma mark Object Specifications
/*!
 * @const IMG4_RUNTIME_OBJECT_SPEC_SUPPLEMENTAL_ROOT
 * The DER representation of the certificate to use as the root of trust for
 * evaluating the supplemental software package. This object can only be
 * executed once for any given boot session.
 */
#if !XNU_KERNEL_PRIVATE
IMG4_API_AVAILABLE_20210205
OS_EXPORT
const img4_runtime_object_spec_t _img4_runtime_object_spec_supplemental_root;
#define IMG4_RUNTIME_OBJECT_SPEC_SUPPLEMENTAL_ROOT \
		(&_img4_runtime_object_spec_supplemental_root)
#else
#define IMG4_RUNTIME_OBJECT_SPEC_SUPPLEMENTAL_ROOT \
		(img4if->i4if_v11.runtime_object_spec_supplemental_root)
#endif

/*!
 * @const IMG4_RUNTIME_OBJECT_SPEC_LOCAL_POLICY
 * The local policy object which has been authorized by the user for a
 * subsequent boot of the system. This object may be executed multiple times in
 * a given boot session. A subsequent local policy must have been authorized by
 * the user after the currently-active one in order to successfully execute.
 */
#if !XNU_KERNEL_PRIVATE
IMG4_API_AVAILABLE_20210205
OS_EXPORT
const img4_runtime_object_spec_t _img4_runtime_object_spec_local_policy;
#define IMG4_RUNTIME_OBJECT_SPEC_LOCAL_POLICY \
		(&_img4_runtime_object_spec_local_policy)
#else
#define IMG4_RUNTIME_OBJECT_SPEC_LOCAL_POLICY \
		(img4if->i4if_v18.runtime_object_spec_local_policy)
#endif

#pragma mark API
/*!
 * @function img4_runtime_find_object_spec
 * Returns the object specification for the given four-character code.
 *
 * @param _4cc
 * The four-character code for which to find the object specification.
 *
 * @result
 * The object specification, or NULL if the four-character code is not an
 * executable object known to the implementation.
 */
#if !XNU_KERNEL_PRIVATE
IMG4_API_AVAILABLE_20210205
OS_EXPORT OS_WARN_RESULT
const img4_runtime_object_spec_t *_Nullable
img4_runtime_find_object_spec(img4_4cc_t _4cc);
#else
#define img4_runtime_find_object_spec(...) \
		(img4if->i4if_v11.runtime_find_object_spec(__VA_ARGS__))
#endif

/*!
 * @function img4_runtime_execute_object
 * Executes an object within the runtime.
 *
 * @param rt
 * The runtime in which to execute the object.
 *
 * @param obj_spec
 * The specification for the object.
 *
 * @param obj
 * The buffer representing the object. The structure and form of the bytes
 * is dictated by the object specification. Usually, these bytes are a wrapped
 * Image4 payload.
 *
 * @param manifest
 * The Image4 manifest authenticating the object. If the object has a manifest
 * stitched to it, this parameter may be NULL.
 *
 * @result
 * Upon success, zero is returned. Otherwise, one of the following error codes:
 *
 *     [EPERM]     The caller does not have permission to set the object
 *     [EALREADY]  The object may only be set once, and it has already been set
 *
 * Any error code returned by {@link img4_firmware_evaluate} may also be
 * returned.
 *
 * Any error code returned by the runtime's {@link i4rt_execute_object} callback
 * will also be returned.
 */
#if !XNU_KERNEL_PRIVATE
IMG4_API_AVAILABLE_20210205
OS_EXPORT OS_WARN_RESULT OS_NONNULL1 OS_NONNULL2 OS_NONNULL3
errno_t
img4_runtime_execute_object(const img4_runtime_t *rt,
		const img4_runtime_object_spec_t *obj_spec,
		const img4_buff_t *obj,
		const img4_buff_t *_Nullable manifest);
#else
#define img4_runtime_execute_object(...) \
		(img4if->i4if_v11.runtime_execute_object(__VA_ARGS__))
#endif

/*!
 * @function img4_runtime_copy_object
 * Copies the payload of an object executed within the runtime.
 *
 * @param rt
 * The runtime in which to query the object.
 *
 * @param obj_spec
 * The specification for the object.
 *
 * @param payload
 * Upon successful return, a pointer to a buffer object which refers to storage
 * that will hold the payload.
 *
 * @param payload_len
 * Upon successful return, a pointer to the total number of bytes coped into the
 * buffer referred to by {@link payload}. This parameter may be NULL.
 *
 * In the event that buffer referred to be {@link payload} is not large enough,
 * this parameter will be set to the total number of bytes required.
 *
 * @result
 * Upon success, zero is returned. Otherwise, one of the following error codes:
 *
 *     [EPERM]    The caller does not have permission to copy the object
 *     [ENOENT]   The requested object is not present
 */
#if !XNU_KERNEL_PRIVATE
IMG4_API_AVAILABLE_20210205
OS_EXPORT OS_WARN_RESULT OS_NONNULL1 OS_NONNULL2 OS_NONNULL3
errno_t
img4_runtime_copy_object(const img4_runtime_t *rt,
		const img4_runtime_object_spec_t *obj_spec,
		img4_buff_t *payload,
		size_t *_Nullable payload_len);
#else
#define img4_runtime_copy_object(...) \
		(img4if->i4if_v11.runtime_copy_object(__VA_ARGS__))
#endif

OS_ASSUME_NONNULL_END

#endif // __IMG4_RUNTIME_H
STAGEEOF
    echo "Staged img4/runtime.h (no KDK)"
fi
if [ ! -f "EXTERNAL_HEADERS/img4/shim.h" ]; then
    mkdir -p "EXTERNAL_HEADERS/img4"
    cat > "EXTERNAL_HEADERS/img4/shim.h" <<'STAGEEOF'
/*!
 * @header
 * Shims for the SPI.
 */
#ifndef __IMG4_SHIM_H
#define __IMG4_SHIM_H

#ifndef __IMG4_INDIRECT
#error "Please #include <img4/firmware.h> instead of this file directly"
#endif // __IMG4_INDIRECT

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#if KERNEL
#define IMG4_TARGET_SHIM_FOUND 1
#define IMG4_TARGET_XNU 1

#if __has_include(<img4/shim_xnu.h>)
#include <img4/shim_xnu.h>
#endif

#if XNU_KERNEL_PRIVATE
#define IMG4_TARGET_XNU_PROPER 1
#else
#define IMG4_TARGET_XNU_PROPER 0
#endif
#endif // KERNEL


#if !IMG4_TARGET_SHIM_FOUND
#if EFI
#define IMG4_TARGET_EFI 1
#if __has_include(<img4/shim_efi.h>)
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wpragma-pack"
#include <img4/shim_efi.h>
#pragma clang diagnostic pop
#endif // __has_include(<img4/shim_efi.h>)
#elif SEP // EFI
#define IMG4_TARGET_SEP 1
#include <img4/shim_sep.h>
#else // EFI
#define IMG4_TARGET_DARWIN 1
#if __has_include(<img4/shim_darwin.h>)
#include <img4/shim_darwin.h>
#endif
#endif // EFI
#endif // !IMG4_TARGET_SHIM_FOUND

#if IMG4_TARGET_XNU || IMG4_TARGET_DARWIN
#define IMG4_TARGET_DARWIN_GENERIC 1
#endif

#endif // __IMG4_SHIM_H
STAGEEOF
    echo "Staged img4/shim.h (no KDK)"
fi
if [ ! -f "EXTERNAL_HEADERS/img4/shim_xnu.h" ]; then
    mkdir -p "EXTERNAL_HEADERS/img4"
    cat > "EXTERNAL_HEADERS/img4/shim_xnu.h" <<'STAGEEOF'
/*!
 * @header
 * Shims for the kernel extension.
 */
#ifndef __IMG4_SHIM_XNU_H
#define __IMG4_SHIM_XNU_H

#ifndef __IMG4_INDIRECT
#error "Please #include <img4/firmware.h> instead of this file directly"
#endif // __IMG4_INDIRECT

#if !XNU_KERNEL_PRIVATE
#include <TargetConditionals.h>
#include <os/availability.h>
#endif

#include <os/base.h>
#include <sys/linker_set.h>
#include <sys/cdefs.h>
#include <stdint.h>
#include <stdbool.h>

#endif // __IMG4_SHIM_XNU_H
STAGEEOF
    echo "Staged img4/shim_xnu.h (no KDK)"
fi
if [ ! -f "EXTERNAL_HEADERS/CodeSignature/Entitlements.h" ]; then
    mkdir -p "EXTERNAL_HEADERS/CodeSignature"
    cat > "EXTERNAL_HEADERS/CodeSignature/Entitlements.h" <<'STAGEEOF'
/*
 * SWEET stand-in for the KDK-only CodeSignature/Entitlements.h.
 * xnu-12377 includes it from kern_exec.c and necp_client.c for the
 * kCSWebBrowser*Entitlement keys. We do NOT declare IOVnodeHasEntitlement
 * here: the real extern prototype lives in <IOKit/IOBSD.h> and its definition
 * in iokit/bsddev/IOKitBSDInit.cpp. A static inline here collides with that
 * extern the moment a TU includes both headers.
 */
#ifndef _SWEET_CODESIGNATURE_ENTITLEMENTS_H
#define _SWEET_CODESIGNATURE_ENTITLEMENTS_H

#include <CoreEntitlements/CoreEntitlements.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Opaque per-process entitlements container (amfi.h references as void*). */
typedef struct OSEntitlements OSEntitlements_t;

/*
 * Web-browser-engine hardened-runtime keys (also defined in the staged
 * CoreEntitlements.h; guarded so this header stands alone if CE is absent).
 */
#ifndef kCSWebBrowserHostEntitlement
#define kCSWebBrowserNetworkEntitlement     (("com.apple.developer.web-browser-engine.networking"))
#define kCSWebBrowserWebContentEntitlement  (("com.apple.developer.web-browser-engine.webcontent"))
#define kCSWebBrowserGPUEntitlement         (("com.apple.developer.web-browser-engine.rendering"))
#define kCSWebBrowserHostEntitlement        (("com.apple.developer.web-browser-engine.host"))
#endif

#ifdef __cplusplus
}
#endif
#endif /* _SWEET_CODESIGNATURE_ENTITLEMENTS_H */
STAGEEOF
    echo "Staged CodeSignature/Entitlements.h (no KDK)"
fi
