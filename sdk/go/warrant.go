// Package warrant 是接入 SDK（Go 版）：三原语 + 状态/复算，只依赖本机 `warrantd`。
//
// ⚠️ **未在本机编译验证**（开发机没有 Go 工具链）。协议与 Python/TypeScript 版逐字节一致
// （`warrantd serve` 的 stdio JSONL），逻辑仅 ~120 行；若编译报错请提 issue，不要自己改协议。
//
// 用法：
//
//	w := warrant.New(".warrant", warrant.WithActor("agent:go"))
//	defer w.Close()
//	claim, _ := w.Act(map[string]any{"file": "out.txt", "bytes": 13}, "写文件")
//	w.Observe(claim, warrant.ChanProcReadback, map[string]any{"file": "out.txt", "bytes": 13}, warrant.TierC1)
//	st, _ := w.Status(claim)   // st["claims"].([]any)[0].(map[string]any)["label"]
package warrant

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"sync"
)

// 观测通道 → 轴：proc_spawn_readback=甲 / mcp_verify_readback=乙 / tool_receipt=丁。
const (
	ChanProcReadback = "proc_spawn_readback"
	ChanSoftwareSelf = "mcp_verify_readback"
	ChanToolReceipt  = "tool_receipt"
)

// 观测档位（C0 最弱，不得支撑冻结）。
const (
	TierC0 = "C0"
	TierC1 = "C1"
	TierC2 = "C2"
	TierC3 = "C3"
)

// Warrant 一份账本 = 一个 root 目录。
type Warrant struct {
	root  string
	actor string
	exe   string

	mu     sync.Mutex
	cmd    *exec.Cmd
	stdin  io.WriteCloser
	stdout *bufio.Reader
}

type Option func(*Warrant)

func WithActor(a string) Option { return func(w *Warrant) { w.actor = a } }
func WithExe(p string) Option   { return func(w *Warrant) { w.exe = p } }

func New(root string, opts ...Option) *Warrant {
	w := &Warrant{root: root, actor: "agent:go", exe: "warrantd"}
	if e := os.Getenv("WARRANTD"); e != "" {
		w.exe = e
	}
	for _, o := range opts {
		o(w)
	}
	return w
}

func (w *Warrant) start() error {
	if w.cmd != nil {
		return nil
	}
	cmd := exec.Command(w.exe, "serve", "--root", w.root)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return err
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("启动 warrantd 失败（PATH 或 WARRANTD 环境变量）：%w", err)
	}
	w.cmd, w.stdin, w.stdout = cmd, stdin, bufio.NewReader(stdout)
	return nil
}

func (w *Warrant) call(req map[string]any) (map[string]any, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if err := w.start(); err != nil {
		return nil, err
	}
	b, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}
	if _, err := w.stdin.Write(append(b, '\n')); err != nil {
		return nil, err
	}
	line, err := w.stdout.ReadBytes('\n')
	if err != nil {
		return nil, fmt.Errorf("warrantd 没有回应（进程已退出？用 Verify 检查账本完整性）：%w", err)
	}
	var resp map[string]any
	if err := json.Unmarshal(line, &resp); err != nil {
		return nil, fmt.Errorf("解析响应失败: %w", err)
	}
	if ok, _ := resp["ok"].(bool); !ok {
		msg, _ := resp["error"].(string)
		return nil, errors.New(msg)
	}
	return resp, nil
}

// Capability 开工声明：我能做什么（进账本 ⇒ 事后不能改口）。
func (w *Warrant) Capability(caps ...string) (map[string]any, error) {
	joined := ""
	for i, c := range caps {
		if i > 0 {
			joined += ","
		}
		joined += c
	}
	return w.call(map[string]any{"op": "capability", "actor": w.actor, "caps": joined})
}

// Act 动手：写一条 claim，返回 claim id。
func (w *Warrant) Act(expect map[string]any, note string) (string, error) {
	if len(expect) == 0 {
		return "", errors.New("expect 必须是非空对象")
	}
	r, err := w.call(map[string]any{"op": "act", "actor": w.actor, "expect": expect, "note": note})
	if err != nil {
		return "", err
	}
	id, _ := r["id"].(string)
	return id, nil
}

// Observe 观测：把"世界看到的结果"挂到 claim 上。轴由 channel 决定（未知通道会被 warrantd 拒绝）。
func (w *Warrant) Observe(claim, channel string, result map[string]any, tier string) (map[string]any, error) {
	if tier == "" {
		tier = TierC1
	}
	return w.call(map[string]any{
		"op": "observe", "actor": w.actor, "subject": claim,
		"channel": channel, "tier": tier, "result": result,
	})
}

// Status 看结论（claim 为空 = 全部）。
func (w *Warrant) Status(claim string) (map[string]any, error) {
	req := map[string]any{"op": "status"}
	if claim != "" {
		req["claim"] = claim
	}
	return w.call(req)
}

// Verify 只读复算：链位 + 签名 + 信任锚。
func (w *Warrant) Verify() (map[string]any, error) { return w.call(map[string]any{"op": "verify"}) }

// Label 便捷：只取 label（FREEZEABLE / TENTATIVE / UNOBSERVED）。
func (w *Warrant) Label(claim string) (string, error) {
	st, err := w.Status(claim)
	if err != nil {
		return "", err
	}
	claims, _ := st["claims"].([]any)
	if len(claims) == 0 {
		return "UNKNOWN", nil
	}
	c, _ := claims[0].(map[string]any)
	l, _ := c["label"].(string)
	return l, nil
}

// Close 关闭守护进程。
func (w *Warrant) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.cmd == nil {
		return nil
	}
	_, _ = w.stdin.Write([]byte("{\"op\":\"quit\"}\n"))
	err := w.cmd.Wait()
	w.cmd, w.stdin, w.stdout = nil, nil, nil
	return err
}
