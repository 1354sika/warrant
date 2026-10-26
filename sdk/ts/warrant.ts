/**
 * Warrant 接入 SDK（TypeScript / Node.js）—— 零依赖，只需要本机有 `warrantd`。
 *
 * 用法：
 *   import { Warrant } from "./warrant";
 *   const w = new Warrant(".warrant", { actor: "agent:ts" });
 *   const claim = await w.act({ file: "out.txt", bytes: 13 });
 *   await w.observe(claim, "proc_spawn_readback", { file: "out.txt", bytes: 13 }, "C1");
 *   console.log(await w.status(claim));   // d_eff / label / state
 *
 * 协议：与 Python SDK 完全一致 —— `warrantd serve --root <dir>`，每行一个 JSON。
 * 轴由 channel 决定：proc_spawn_readback=甲 / mcp_verify_readback=乙 / tool_receipt=丁。
 */

import { spawn, type ChildProcessWithoutNullStreams } from "node:child_process";

export const CHANNELS = ["proc_spawn_readback", "mcp_verify_readback", "tool_receipt"] as const;
export const TIERS = ["C0", "C1", "C2", "C3"] as const;
export type Channel = (typeof CHANNELS)[number];
export type Tier = (typeof TIERS)[number];

export class WarrantError extends Error {}

/** SPEC §3 严格档：只允许整数，浮点会破坏规范序列化的可比性。 */
function strict(v: unknown): unknown {
  if (typeof v === "number" && !Number.isInteger(v)) {
    throw new WarrantError(`严格档不接受浮点数（${v}）：请改用整数或字符串`);
  }
  if (Array.isArray(v)) return v.map(strict);
  if (v && typeof v === "object") {
    const out: Record<string, unknown> = {};
    for (const [k, val] of Object.entries(v as Record<string, unknown>)) out[k] = strict(val);
    return out;
  }
  return v;
}

export interface WarrantOptions {
  actor?: string;
  exe?: string;
}

export class Warrant {
  readonly root: string;
  readonly actor: string;
  private readonly exe: string;
  private proc: ChildProcessWithoutNullStreams | null = null;
  private buf = "";
  private pending: Array<(line: string) => void> = [];

  constructor(root = ".warrant", opts: WarrantOptions = {}) {
    this.root = root;
    this.actor = opts.actor ?? "agent:ts";
    this.exe = opts.exe ?? process.env.WARRANTD ?? "warrantd";
  }

  private ensure(): ChildProcessWithoutNullStreams {
    if (this.proc && this.proc.exitCode === null) return this.proc;
    const p = spawn(this.exe, ["serve", "--root", this.root], { stdio: ["pipe", "pipe", "ignore"] });
    p.stdout.setEncoding("utf8");
    p.stdout.on("data", (chunk: string) => {
      this.buf += chunk;
      let i: number;
      while ((i = this.buf.indexOf("\n")) >= 0) {
        const line = this.buf.slice(0, i);
        this.buf = this.buf.slice(i + 1);
        const cb = this.pending.shift();
        if (cb) cb(line);
      }
    });
    this.proc = p;
    return p;
  }

  private call(req: Record<string, unknown>): Promise<Record<string, any>> {
    return new Promise((resolve, reject) => {
      const p = this.ensure();
      this.pending.push((line) => {
        try {
          const resp = JSON.parse(line);
          if (!resp.ok) reject(new WarrantError(resp.error ?? "未知错误"));
          else resolve(resp);
        } catch (e) {
          reject(new WarrantError(`解析 warrantd 响应失败: ${String(e)}`));
        }
      });
      p.stdin.write(JSON.stringify(req) + "\n");
    });
  }

  /** 开工声明：我能做什么（进账本 ⇒ 事后不能改口）。 */
  capability(caps: string[], actor?: string) {
    return this.call({ op: "capability", actor: actor ?? this.actor, caps: caps.join(",") });
  }

  /** 动手：写一条 claim，返回 claim id。 */
  async act(expect: Record<string, unknown>, note = "", actor?: string): Promise<string> {
    if (!expect || typeof expect !== "object" || Object.keys(expect).length === 0) {
      throw new WarrantError("expect 必须是非空对象");
    }
    const r = await this.call({ op: "act", actor: actor ?? this.actor, expect: strict(expect), note });
    return r.id as string;
  }

  /** 观测：把"世界看到的结果"挂到 claim 上；轴由 channel 决定。 */
  observe(claim: string, channel: Channel, result: Record<string, unknown>, tier: Tier = "C1", actor?: string) {
    if (!CHANNELS.includes(channel)) throw new WarrantError(`未知 channel ${channel}`);
    if (!TIERS.includes(tier)) throw new WarrantError(`未知 tier ${tier}`);
    return this.call({ op: "observe", actor: actor ?? this.actor, subject: claim, channel, tier, result: strict(result) });
  }

  status(claim?: string) {
    return this.call(claim ? { op: "status", claim } : { op: "status" });
  }

  verify() {
    return this.call({ op: "verify" });
  }

  async label(claim: string): Promise<string> {
    const st = await this.status(claim);
    return st.claims?.[0]?.label ?? "UNKNOWN";
  }

  close(): void {
    if (this.proc && this.proc.exitCode === null) {
      try {
        this.proc.stdin.write('{"op":"quit"}\n');
      } catch {
        /* 忽略 */
      }
      this.proc.kill();
    }
    this.proc = null;
  }
}
