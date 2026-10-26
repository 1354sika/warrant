"""CLI 冒烟：把 warrantd 的每条命令按真实用法跑一遍（不是库 API，是命令行）。

跑法（在仓库根）：
    set WARRANTD=target\\debug\\warrantd.exe
    python _scratch/smoke_cli.py
"""
import json
import os
import shutil
import subprocess
import sys
import tempfile

EXE = os.environ.get("WARRANTD", "warrantd")
ROOT = tempfile.mkdtemp(prefix="warrant-cli-")
LEDGER = os.path.join(ROOT, ".warrant")
KEY = os.path.join(ROOT, "human.key.json")


def run(*args, expect_ok=True):
    p = subprocess.run([EXE, *args], capture_output=True, text=True, encoding="utf-8")
    out = (p.stdout or "").strip()
    try:
        j = json.loads(out.splitlines()[-1]) if out else {}
    except Exception:
        j = {"_raw": out, "_err": p.stderr}
    if expect_ok and not j.get("ok"):
        print(f"[FAIL] {' '.join(args)}\n  -> {out}\n  stderr={p.stderr}")
        sys.exit(1)
    return j


print(f"root = {ROOT}")

j = run("keygen", "--out", KEY)
key_id = j["key_id"]
print(f"1 keygen   -> {key_id[:24]}...")

run("trust", "--root", LEDGER, "--key-id", key_id, "--note", "smoke")
print("2 trust    -> ok")

run("capability", "--root", LEDGER, "--actor", "agent:cli", "--caps", "write_file,read_file")
print("3 capabil. -> ok")

# 实际要观测的目标（先落盘，再让 agent 声称结果）
target = os.path.join(ROOT, "out.txt")
with open(target, "wb") as f:
    f.write(b"hello warrant")

claim = run("act", "--root", LEDGER, "--actor", "agent:cli",
            "--expect", json.dumps({"file": target, "bytes": 13}, ensure_ascii=False),
            "--note", "写文件")["id"]
print(f"4 act      -> {claim[:20]}...")

# ✅ 重要语义：`expect` 里的**每一个键都必须在观测结果里出现且相等**，否则算 `unknown`
#   （unknown / contradicted → 都不算支持证据 → 不产轴）。所以两边用同一组键与同一个路径。
probe = os.path.join(ROOT, "probe.py")
with open(probe, "w", encoding="utf-8") as f:
    f.write(
        "import json, os, sys\n"
        "p = sys.argv[1]\n"
        "print(json.dumps({'file': p, 'bytes': os.path.getsize(p)}))\n"
    )
print(f"   实测字节 = {os.path.getsize(target)}")
# 甲轴：命令由 warrantd 自己跑（stdout 即 result）。
# 注意：warrantd 用 `cmd /C` 执行，命令以引号开头会被 cmd 剥引号 ⇒ 用 .bat 包装（真实用法也推荐这样）。
launcher = os.path.join(ROOT, "probe.bat")
with open(launcher, "w", encoding="utf-8") as f:
    f.write(f'@echo off\n"{sys.executable}" "{probe}" "{target}"\n')
o1 = run("observe", "--root", LEDGER, "--actor", "engine:rb", "--subject", claim,
         "--channel", "proc_spawn_readback", "--tier", "C1",
         "--exec", launcher)
print(f"5 observe  -> axis={o1.get('axis')} (exec 采集)")

# 乙轴：被控软件自报（这里由脚本直接给 result，代表"软件回读"）
run("observe", "--root", LEDGER, "--actor", "tool:fs", "--subject", claim,
    "--channel", "mcp_verify_readback", "--tier", "C1",
    "--result", json.dumps({"file": target, "bytes": 13}, ensure_ascii=False))
print("6 observe  -> axis=乙")

st = run("status", "--root", LEDGER, "--claim", claim)["claims"][0]
print(f"7 status   -> state={st['state']} label={st['label']} d_eff={st['d_eff']} axes={st['axes']}")
assert st["label"] == "FREEZEABLE", st

fr = run("freeze", "--root", LEDGER, "--claim", claim, "--key", KEY, "--signer", "user:smoke", "--reason", "冒烟")
c = fr["claims"][0]
print(f"8 freeze   -> state={c['state']} label={c['label']}")
assert c["state"] == "WARRANTED", c

v = run("verify", "--root", LEDGER)
print(f"9 verify   -> chain={len(v['chain_errors'])} sig={len(v['signature_errors'])} trust={len(v['trust_errors'])} keys={v['trusted_keys']}")
assert not v["chain_errors"] and not v["signature_errors"] and not v["trust_errors"], v

# 第二本账（模拟另一台机器），聚合数轴
other = os.path.join(ROOT, ".warrant-b")
run("act", "--root", other, "--actor", "agent:b", "--expect", '{"k":"v"}', "--note", "另一台")
agg = subprocess.run([EXE, "aggregate", LEDGER, other], capture_output=True, text=True, encoding="utf-8")
aj = json.loads(agg.stdout.strip().splitlines()[-1])
print(f"10 aggregate-> ok={aj['ok']} roots={len(aj['roots'])} merged={aj['merged_entries']} claims={len(aj['claims'])}")
assert aj["ok"] and len(aj["roots"]) == 2

print("\nOK：CLI 全链路（keygen→trust→act→observe(--exec)→freeze→verify→aggregate）跑通")
shutil.rmtree(ROOT, ignore_errors=True)
