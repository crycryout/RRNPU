This is the code of undergrad thesis project: RRNPU
the target machine is i.MX93
to build recorder:
cd recorder/boards/mcimx93evk/demo_apps/ethosu_apps/armgcc/
run ./build_release.sh
to build replayer:
cd replayer/boards/mcimx93evk/demo_apps/ethosu_apps/armgcc/
to build elf that run in TEE
cd replayer/boards/mcimx93evk/trustzone_examples/hello_world/hello_world_s/armgcc/
run ./build_realease.sh
to build optee-os
cd optee-os
run make CFG_ARM64_core=y      CFG_TEE_BENCHMARK=n      CFG_TEE_CORE_LOG_LEVEL=4      CROSS_COMPILE=aarch64-linux-gnu-      CROSS_COMPILE_core=aarch64-linux-gnu-      CROSS_COMPILE_ta_arm64=aarch64-linux-gnu-      DEBUG=1      PLATFORM=out/arm      PLATFORM=imx      PLATFORM_FLAVOR=mx93evk
to build optee-inference_ta_and_client
cd optee_inference_ta_and_client/ocram_load/client
run
make     CROSS_COMPILE=aarch64-linux-gnu-     TEEC_EXPORT=~/optee_export     --no-builtin-variables
cd optee_inference_ta_and_client/ocram_load/ta
run
make     CROSS_COMPILE=aarch64-linux-gnu-     PLATFORM=imx     PLATFORM_FLAVOR=mx93evk     TA_DEV_KIT_DIR=~/ethosu/optee/imx-optee-os/out/arm/export-ta_arm64

