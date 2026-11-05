# AgentCap

**Attestation-Bound, Offline-Attenuable Delegation for LLM Multi-Agent Systems in Distributed Edge Environments**

Source code, measured data, figure sources and LaTeX manuscript for the paper submitted to *Cluster Computing* (Springer).

AgentCap lets LLM agents delegate authority over IoT devices hop by hop, offline, while every hop is bound to the remote-attestation evidence of the receiving agent runtime. A microcontroller verifies the whole chain with symmetric cryptography only. Chained HMAC tags are used as *possession keys*, never as tokens: each tag is sealed to an attested runtime and only answers a device challenge. One 8-byte identifier revokes an agent together with its entire delegation sub-tree.

## Key results (Cortex-M4 @ 64 MHz, delegation depth 3)

| Verifier | Cycles | Time | Flash (-Os) | Non-bearer | Offline attenuation | Attestation-bound |
|---|---:|---:|---:|:-:|:-:|:-:|
| **AgentCap (cold)** | 97.1 k | 1.52 ms | 2.9 KB | yes | yes | yes |
| **AgentCap (cached)** | 12.9 k | 0.20 ms | 3.5 KB | yes | yes | yes |
| Macaroon (bearer) | 73.1 k | 1.14 ms | 2.9 KB | no | yes | no |
| ACE-OAuth symmetric PoP | 91.2 k | 1.43 ms | 4.0 KB | yes | no (online AS) | no |
| UCAN (Ed25519 chain) | 10.3 M | 161 ms | 14.4 KB | yes | yes | no |
| OAuth JWT (ES256) | 11.9 M | 186 ms | 12.7 KB | no | no | no |
| OAuth token exchange + DPoP | 24.2 M | 377 ms | 12.7 KB | yes | no | no |

Results are also reported for Cortex-M0+ and RV32IMC. AgentCap rejected attack classes A1–A7 in every trial (forwarding, replay, tampering, truncation, rogue sub-agent, cross-device reuse, forgery; 1000 trials each). In a five-seed prompt-injection study it executed no out-of-intent command, while OAuth device:action scopes did so in 68.8 ± 2.6 % of sessions.

System level: one hub core issues about 2,700 attested root credentials per second (two processes: 1.8-2.0x); with one 0.6 KB cache entry per concurrent chain, 95-99.7 % of verifications hit the cache; delegation is unaffected by cloud outages, whereas online-AS schemes complete 71-78 % of two-hop delegations at 30 % unreachability. A closed-form model, 5*kappa*(n+1) SHA-256 compressions, predicts cold verification cycles on all three ISAs within 0.2 %.

Corresponding author: Salahaldeen Duraibi (sduraibi@jazanu.edu.sa).

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
figs/          TikZ/PGFPlots sources of all 15 figures (+ wrap.sh standalone preview)
paper/         Springer sn-jnl LaTeX submission bundle, compiled main.pdf, figure PDFs (Fig1-Fig15)
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

## Measurement methodology and limits

Device verifiers are compiled with Clang for each ISA and executed in the Unicorn emulator. Executed-instruction counts are exact. Cycle counts come from documented per-ISA in-order timing models (see `py/mcuemu.py` and the per-ISA timing-model table of the paper) and assume zero flash wait states. Agent-side timings are host medians of seven rounds. The attestation vendor is simulated with an Ed25519 key, and the prompt-injection study evaluates the enforcement layer against injected command streams rather than a production LLM. See the Discussion and Limitations section of the paper.

## Paper

`paper/` uses the Springer Nature `sn-jnl` class (bundled) and compiles to `paper/main.pdf` with `pdflatex main; bibtex main; pdflatex main; pdflatex main`. Figures are included as vector PDFs from `paper/figs/`; their TikZ/PGFPlots sources are in `figs/`.

## Citation

If you use this code, please cite the paper (see `CITATION.cff`).

## License

The code in this repository is released under the MIT License (see `LICENSE`). Third-party libraries keep their own licenses.
