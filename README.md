# RRNPU

> Undergraduate thesis project for secure NPU-driven inference.
> **Target machine:** NXP i.MX93

---

## Table of Contents

1. [Build Recorder](#build-recorder)
2. [Build Replayer](#build-replayer)
3. [Build “Hello World” TA](#build-hello-world-ta)
4. [Build OP-TEE OS](#build-op-tee-os)
5. [Build OP-TEE Inference TA & Client](#build-op-tee-inference-ta--client)

---

## Build Recorder

```bash
cd recorder/boards/mcimx93evk/demo_apps/ethosu_apps/armgcc/
./build_release.sh
```

---

## Build Replayer

```bash
cd replayer/boards/mcimx93evk/demo_apps/ethosu_apps/armgcc/
./build_release.sh
```

---

## Build “Hello World” TA

```bash
cd replayer/boards/mcimx93evk/trustzone_examples/hello_world/hello_world_s/armgcc/
./build_release.sh
```

---

## Build OP-TEE OS

```bash
cd optee-os
make \
  CFG_ARM64_core=y \
  CFG_TEE_BENCHMARK=n \
  CFG_TEE_CORE_LOG_LEVEL=4 \
  CROSS_COMPILE=aarch64-linux-gnu- \
  CROSS_COMPILE_core=aarch64-linux-gnu- \
  CROSS_COMPILE_ta_arm64=aarch64-linux-gnu- \
  DEBUG=1 \
  PLATFORM=out/arm \
  PLATFORM=imx \
  PLATFORM_FLAVOR=mx93evk
```

---

## Build OP-TEE Inference TA & Client

### Client

```bash
cd optee_inference_ta_and_client/ocram_load/client
make CROSS_COMPILE=aarch64-linux-gnu-
```

### TA

```bash
cd optee_inference_ta_and_client/ocram_load/ta
make \
  CROSS_COMPILE=aarch64-linux-gnu- \
  PLATFORM=imx \
  PLATFORM_FLAVOR=mx93evk \
  TA_DEV_KIT_DIR=~/ethosu/optee/imx-optee-os/out/arm/export-ta_arm64
```
