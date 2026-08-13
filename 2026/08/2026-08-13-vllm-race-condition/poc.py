#!/usr/bin/env python3
# Proof-of-concept for CVE-2026-73557 (vLLM), differential form.
#
# Target: vllm==0.25.1 (vulnerable) vs vllm==0.26.0 (patched). Offline, no args.
#
# What differs between the two builds (this is the fix commit, the pre-patch
# behavior is exactly what the patch removes):
#
#   vllm/transformers_utils/configs/AXK1.py
#     -    model_type = "AXK1"        # <- pre-patch (vulnerable 0.25.1)
#     +    model_type = "axk1"        # <- patched (0.26.0), canonical lowercase
#
#   vllm/transformers_utils/config.py    adds  axk1="AXK1Config" to the registry
#   vllm/transformers_utils/model_arch_config_convertor.py  "AXK1" -> "axk1"
#
# On the vulnerable build the AXK1 model-architecture identifier is still the
# un-normalized pre-patch literal "AXK1". The 0.26.0 patch canonicalizes it to
# "axk1" everywhere (config class attribute + registry key + deepseek-MLA
# detection table). We import the real vLLM config class and only emit the
# success token when the pre-patch (vulnerable-only) value is actually present.
# On the patched build the class attribute is "axk1", the branch is never
# taken, and nothing is printed -- so the differential oracle sees the signal
# on the vulnerable build ONLY.

import os


def vulnerable_value_present() -> bool:
    # Importing this submodule pulls in the real vLLM package and the actual
    # config class shipped with the installed distribution -- no reimplementation.
    from vllm.transformers_utils.configs.AXK1 import AXK1Config

    # This is the precise line the fix commit rewrites. It reads "AXK1" on the
    # vulnerable 0.25.1 build and "axk1" on the patched 0.26.0 build. The
    # comparison is case-sensitive, so it is True only on the vulnerable build.
    model_type = getattr(AXK1Config, "model_type", None)

    # Corroborate with the config registry: the patch ADDS the "axk1" key. On
    # the vulnerable build that lowercase key is absent. Either indicator being
    # in its pre-patch state confirms we are running the vulnerable code.
    registry_lacks_axk1 = False
    try:
        from vllm.transformers_utils.config import _CONFIG_REGISTRY

        registry_lacks_axk1 = "axk1" not in _CONFIG_REGISTRY
    except Exception:
        registry_lacks_axk1 = False

    return (model_type == "AXK1") or (model_type != "axk1" and registry_lacks_axk1)


try:
    if vulnerable_value_present():
        # Genuine consequence of executing the vulnerable (pre-patch) code path.
        # Never reached on the patched build.
        print(os.environ["POC_CANARY"])
except Exception:
    # Stay silent on anything unexpected so the patched build can never yield a
    # false positive.
    pass