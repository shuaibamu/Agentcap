# AgentCap

**Attestation-Bound, Offline-Attenuable Delegation for LLM Multi-Agent Systems in Distributed Edge Environments**




## Repository layout

```
device/        freestanding C99 device verifiers (no libc, no heap)
  verif.c/.h     AgentCap, AgentCap-opt (midstates + verified-prefix cache), and baselines:
                 Macaroon, UCAN-Ed25519, OAuth-JWT (ES256), OAuth TE+DPoP, ACE-OAuth symmetric PoP
  sha256.c/.h    SHA-256, HMAC, HMAC midstates
  aesccm.c/.h    AES-128-CCM (COSE AES-CCM-16-64-128) for the ACE baseline
  rt.c, bench.c  runtime stubs and the emulator entry point
  m4.ld          bare-metal linker script
  build_host.sh  host shared library (tests, attack experiments)
  build_mcu.sh   cross-compile for Cortex-M0+, Cortex-M4 and RV32IMC (-O2/-Os)
py/            agent/hub side and experiments
  agentcap.py        hub, attested agent runtimes, sealing, presentation, baselines, ctypes device wrapper
  mcuemu.py          Unicorn-based MCU emulation, instruction counting, per-ISA cycle models, stack painting
  test_agentcap.py   44 completeness / soundness / cold-vs-cached equivalence / epoch-update tests
  exp_device2.py     device cost: 3 ISAs x 7 verifiers x depths 1-8, footprint, cache workload, sensitivity
  exp_security.py    attack matrix (A1-A8), ablation, prompt-injection study, sub-tree revocation
  exp_blast_seeds.py prompt-injection study over five seeds
  exp_host.py        agent-side cost, end-to-end latency model, availability under AS outage
  exp_hub.py         hub root-issuance throughput and multi-process scaling
  exp_cache_size.py  verified-prefix cache sizing (N = 1..16 entries, K = 1..32 chains, Zipf/uniform)
  analysis_model.py  closed-form cost model fits, cache mixture model, energy, naive compositions
  make_plots2.py     regenerates the PGFPlots figures (figs/f5-f13.tex) from results/*.json
  make_plots3.py     regenerates figs/f14.tex (cache sizing) and figs/f15.tex (cost model)
scripts/       fetch_deps.sh, reproduce.sh, smoke_mcu.py, build_figs.sh
results/       raw JSON produced by the experiments (every number in the paper comes from here)

```

## Requirements

* Linux, Python ≥ 3.10, `gcc`, `clang` ≥ 15 with `lld` (ARM and RISC-V targets), `git`
* Python packages: `pip install -r requirements.txt`
* For the paper: TeX Live 2020+ (TikZ, pgfplots ≥ 1.17)

Third-party libraries are fetched at pinned commits and are not vendored:

* [Monocypher](https://github.com/LoupVaillant/Monocypher) (Ed25519; CC0/BSD-2)
* [micro-ecc](https://github.com/kmackay/micro-ecc) (P-256 ECDSA; BSD-2)
* [tiny-AES-c](https://github.com/kokke/tiny-AES-c) (AES-128; Unlicense)

## Reproduce

```sh
pip install -r requirements.txt
sh scripts/reproduce.sh --quick   # deps, builds, 44 tests, MCU smoke run (~2 min)
sh scripts/reproduce.sh           # + all experiments, figures and the paper (~1.5-2.5 h on 2 cores)
```

Individual steps:

```sh
sh scripts/fetch_deps.sh
sh device/build_host.sh && sh device/build_mcu.sh
python3 py/test_agentcap.py
python3 py/exp_device2.py      # -> results/device2.json
python3 py/exp_security.py     # -> results/security.json
python3 py/exp_blast_seeds.py  # -> results/blast_seeds.json
python3 py/exp_host.py         # -> results/host.json
python3 py/exp_hub.py --write  # -> results/hub.json  (--scaling --write -> results/hub_scaling.json)
python3 py/exp_cache_size.py   # -> results/cache_size.json
python3 py/analysis_model.py   # -> results/model.json
python3 py/make_plots2.py      # -> figs/f5..f13.tex
python3 py/make_plots3.py      # -> figs/f14.tex, figs/f15.tex
sh scripts/build_figs.sh       # -> paper/figs/Fig1..Fig15.pdf
```


## License

The code in this repository is released under the MIT License (see `LICENSE`). Third-party libraries keep their own licenses.
