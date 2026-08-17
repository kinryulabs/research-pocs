import os

CANARY_KEY = "POC_CANARY"


def _emit():
    # Only reached when the pre-patch code path is actually taken.
    print(os.environ[CANARY_KEY])


def _try_is_deepseek_mla():
    """Exercise the exact line the fix changed.

    In vulnerable 0.25.1, `is_deepseek_mla` treats the model_type spelled
    "AXK1" as a recognized MLA architecture (it is a member of the
    hard-coded set). The 0.26.0 patch renamed that entry to the lowercase
    "axk1" (and registered it in _CONFIG_REGISTRY), so a config object still
    carrying the "AXK1" spelling no longer matches and the method returns
    False. We drive the real, unmodified method with a minimal stand-in
    config so the observed True/False is produced by the shipped code.
    """
    import inspect
    from vllm.transformers_utils import model_arch_config_convertor as mod

    func = None
    for obj in vars(mod).values():
        if inspect.isclass(obj) and "is_deepseek_mla" in getattr(obj, "__dict__", {}):
            func = obj.__dict__["is_deepseek_mla"]
            break
    if func is None:
        raise RuntimeError("is_deepseek_mla not found")

    class _HF:
        model_type = "AXK1"   # spelling recognized only on the vulnerable build
        kv_lora_rank = 1      # non-None so the matched branch resolves truthy
        model = None

    class _Cfg:
        hf_text_config = _HF()

    return bool(func(_Cfg()))


triggered = None
try:
    triggered = _try_is_deepseek_mla()
except Exception:
    triggered = None

if triggered is True:
    # Vulnerable build: the "AXK1"-spelled config was accepted as MLA.
    _emit()
elif triggered is None:
    # Import/shape mismatch: fall back to the same differential read straight
    # off the patched attribute. Pre-patch the class advertises "AXK1";
    # the fix lowercases it to "axk1", so this is False on a patched build.
    try:
        from vllm.transformers_utils.configs.AXK1 import AXK1Config

        if getattr(AXK1Config, "model_type", None) == "AXK1":
            _emit()
    except Exception:
        pass