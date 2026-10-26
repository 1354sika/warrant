"""Warrant 接入 SDK —— 三行把任何 agent 接上认定层。

用法（Python 3.8+，零第三方依赖）：

    from warrant import Warrant
    w = Warrant(".warrant")
    claim = w.act({"file": "out.txt", "bytes": 12}, note="写文件")
    w.observe(claim, "proc_spawn_readback", {"file": "out.txt", "bytes": 12}, tier="C1")
    print(w.status(claim))      # d_eff / label / state

它做了什么：**记录**（写进链式账本）+ **判定**（数独立来源，`d_eff`）+ **卡出口**
（`d_eff < 2` 或没有非 AI 轴 ⇒ 只能说 TENTATIVE）。
它不做什么：不阻止 agent 撒谎，也不读你的日志内容 —— 它只数"有几个独立来源看到了"。

三原语（对应 ADAPTER.md）：
  capability(actor, caps)                      —— 开工前声明"我能做什么"
  act(expect, note)                            —— 动手，带上**之后要拿来比对的预期**
  observe(claim, channel, result, tier)        —— 观测；**轴由 channel 决定**

通道 → 轴（写错的通道会直接报错，不会静默降级）：
  proc_spawn_readback  甲  我方独立通道（新进程读回 / 离线复算）
  mcp_verify_readback  乙  被控软件自报（同 server 只读回读）
  tool_receipt         丁  AI 自报（最弱，永不计入够格）
  （丙 = 人，走签名，不由本 SDK 产生）

要求：本机有 `warrantd` 可执行文件（`cargo install --path .` 或设环境变量 `WARRANTD`）。
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from typing import Any, Dict, Iterable, List, Optional

__all__ = ["Warrant", "WarrantError", "CHANNELS", "TIERS"]

CHANNELS = ("proc_spawn_readback", "mcp_verify_readback", "tool_receipt")
TIERS = ("C0", "C1", "C2", "C3")


class WarrantError(RuntimeError):
    """接入层返回的错误（参数非法 / 通道未知 / 账本被占用等）。"""


def _strict(obj: Any) -> Any:
    """把 Python 对象转成规范档允许的 JSON 形状：**禁 float**（SPEC §3 只允许整数）。

    浮点在规范序列化里没有定义 ⇒ 与其让底层报"不是合法 JSON"，不如在这里说清原因。
    """
    if isinstance(obj, float):
        raise WarrantError(
            f"严格档不接受浮点数（{obj!r}）：请改用整数或字符串（例如毫秒整数、'12.5'）"
        )
    if isinstance(obj, dict):
        return {str(k): _strict(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [_strict(v) for v in obj]
    if isinstance(obj, (str, int, bool)) or obj is None:
        return obj
    raise WarrantError(f"不支持的 JSON 值类型：{type(obj).__name__}")


class Warrant:
    """一份账本 = 一个 root 目录。线程内用；跨线程请各自建实例或加锁。"""

    def __init__(self, root: str = ".warrant", exe: Optional[str] = None, actor: str = "agent:python"):
        self.root = root
        self.actor = actor
        self._exe = exe or os.environ.get("WARRANTD") or shutil.which("warrantd")
        if not self._exe:
            raise WarrantError(
                "找不到 warrantd 可执行文件：请 `cargo install --path .`，"
                "或用 Warrant(exe=r'...\\warrantd.exe') 指定，或设环境变量 WARRANTD"
            )
        self._proc: Optional[subprocess.Popen] = None

    # ---------------- 三原语 ----------------

    def capability(self, caps: Iterable[str], actor: Optional[str] = None) -> Dict[str, Any]:
        """开工声明：我能做什么（进账本 ⇒ 事后不能改口）。"""
        return self._call({"op": "capability", "actor": actor or self.actor, "caps": ",".join(caps)})

    def act(self, expect: Dict[str, Any], note: str = "", actor: Optional[str] = None) -> str:
        """动手：写一条 claim，返回 claim id（之后 observe 要挂到它上面）。"""
        if not isinstance(expect, dict) or not expect:
            raise WarrantError("expect 必须是非空 dict（例如 {'file': 'out.txt'}）：它要能和观测结果逐键比对")
        r = self._call({"op": "act", "actor": actor or self.actor, "expect": _strict(expect), "note": note})
        return r["id"]

    def observe(
        self,
        claim: str,
        channel: str,
        result: Dict[str, Any],
        tier: str = "C1",
        actor: Optional[str] = None,
    ) -> Dict[str, Any]:
        """观测：把"世界看到的结果"挂到 claim 上。返回含 `axis` 的回执。"""
        if channel not in CHANNELS:
            raise WarrantError(f"未知 channel {channel!r}（可选 {CHANNELS}）：编个名字骗不到轴")
        if tier not in TIERS:
            raise WarrantError(f"未知 tier {tier!r}（可选 {TIERS}）")
        if not isinstance(result, dict):
            raise WarrantError("result 必须是 dict")
        return self._call(
            {
                "op": "observe",
                "actor": actor or self.actor,
                "subject": claim,
                "channel": channel,
                "tier": tier,
                "result": _strict(result),
            }
        )

    # ---------------- 读结论 ----------------

    def status(self, claim: Optional[str] = None) -> Dict[str, Any]:
        """看结论：每条 claim 的 state / label / d_eff / 轴。"""
        req: Dict[str, Any] = {"op": "status"}
        if claim:
            req["claim"] = claim
        return self._call(req)

    def verify(self) -> Dict[str, Any]:
        """只读复算：链位 + 签名。第三方拿到同一份 entries.jsonl 也能跑出同样结果。"""
        return self._call({"op": "verify"})

    def label(self, claim: str) -> str:
        """便捷：只取 label（FREEZEABLE / TENTATIVE / UNOBSERVED）。"""
        st = self.status(claim)
        claims = st.get("claims") or []
        return claims[0].get("label", "UNKNOWN") if claims else "UNKNOWN"

    # ---------------- 传输层 ----------------

    def _ensure_proc(self) -> subprocess.Popen:
        if self._proc is None or self._proc.poll() is not None:
            self._proc = subprocess.Popen(
                [self._exe, "serve", "--root", self.root],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                text=True,
                encoding="utf-8",
                bufsize=1,
            )
        return self._proc

    def _call(self, req: Dict[str, Any]) -> Dict[str, Any]:
        p = self._ensure_proc()
        assert p.stdin and p.stdout
        p.stdin.write(json.dumps(req, ensure_ascii=False) + "\n")
        p.stdin.flush()
        line = p.stdout.readline()
        if not line:
            raise WarrantError("warrantd 没回应（进程已退出？用 verify() 检查账本完整性）")
        resp = json.loads(line)
        if not resp.get("ok"):
            raise WarrantError(resp.get("error", "未知错误"))
        return resp

    def close(self) -> None:
        if self._proc and self._proc.poll() is None:
            try:
                assert self._proc.stdin
                self._proc.stdin.write('{"op":"quit"}\n')
                self._proc.stdin.flush()
            except Exception:
                pass
            try:
                self._proc.wait(timeout=3)
            except Exception:
                self._proc.kill()
        self._proc = None

    def __enter__(self) -> "Warrant":
        return self

    def __exit__(self, *exc: Any) -> None:
        self.close()
