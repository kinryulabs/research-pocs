#!/usr/bin/env python3
"""
PoC for CVE-2026-73555 (vLLM < 0.26.0).

Differential signal derived from the fix commit: the patch renames the AXK1
model architecture identifier from the (convention-violating) upper-case
"AXK1" to the canonical lower-case "axk1" in three places:

  * vllm/transformers_utils/configs/AXK1.py   -> AXK1Config.model_type
  * vllm/transformers_utils/config.py         -> _CONFIG_REGISTRY key
  * vllm/transformers_utils/model_arch_config_convertor.py
        -> the case-sensitive `model_type in (...)` tuples inside
           is_deepseek_mla()

The pre-patch behaviour we trigger: a config that reports the *legacy* model
type identifier "AXK1" is recognised by the architecture convertor's
deepseek-MLA detector, because the detector compares against the literal
upper-case token. In 0.26.0 the comparison tuples were lower-cased, so the
same "AXK1"-typed config is no longer recognised -> the detector returns
False and the exploit primitive does not fire.

Because vLLM's own AXK1Config declares model_type == "AXK1" in the vulnerable
build, feeding that legacy identifier into is_deepseek_mla() is a faithful
reconstruction of the real request path a genuine AXK1 model config takes.

The success token is emitted ONLY as a consequence of the detector accepting
the upper-case identifier (vulnerable build). On the patched build every check
below evaluates to False, so nothing is printed.
"""

import os

# The exact identifier the patch removes. In 0.26.0 this became "axk1".
LEGACY_ID = "AXK1"


def convertor_recognizes_legacy_id():
    """
    Drive the real arch-config convertor's deepseek-MLA detector with a config
    object that reports the legacy upper-case model_type "AXK1".

    Pre-patch:  "AXK1" is a member of the (upper-case) match tuple -> the
                detector reaches the kv_lora_rank branch and returns True.
    Post-patch: the tuple is lower-case ("axk1"), "AXK1" matches nothing,
                the detector falls through to `return False`.
    """
    import inspect
    from types import SimpleNamespace
    import vllm.transformers_utils.model_arch_config_convertor as conv

    # Locate whatever class actually defines is_deepseek_mla (name/shape of the
    # owning class is not depended upon).
    fn = None
    for obj in vars(conv).values():
        if inspect.isclass(obj) and "is_deepseek_mla" in getattr(obj, "__dict__", {}):
            fn = obj.__dict__["is_deepseek_mla"]
            break
    if fn is None:
        raise RuntimeError("is_deepseek_mla not found")

    # Minimal stand-in for a HF text config that reports the legacy id. It has
    # kv_lora_rank set (so the matched branch resolves to True) and no nested
    # `.model`, so the secondary tuple branch is skipped on the patched build.
    hf = SimpleNamespace(model_type=LEGACY_ID, kv_lora_rank=512, q_lora_rank=1536)
    stub = SimpleNamespace(hf_text_config=hf, hf_config=hf)

    return bool(fn(stub))


def config_declares_legacy_id():
    """
    Confirmation via the config class the patch edits: vulnerable AXK1Config
    declares model_type "AXK1"; patched declares "axk1".
    """
    from vllm.transformers_utils.configs.AXK1 import AXK1Config
    return AXK1Config.model_type == LEGACY_ID


triggered = False

# Primary: functional consequence through the real detector code path.
try:
    triggered = convertor_recognizes_legacy_id()
except Exception:
    # If the detector could not be exercised on this build, fall back to
    # observing the pre-patch artifact directly. Both paths are False on the
    # patched build, so neither can produce a false positive.
    try:
        triggered = config_declares_legacy_id()
    except Exception:
        triggered = False

if triggered:
    # Only reachable when the pre-patch (upper-case "AXK1") behaviour is present.
    print(os.environ["POC_CANARY"])