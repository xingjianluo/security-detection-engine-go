package alert

import (
	"encoding/binary"
	"hash/fnv"
)

// alertID 由 (租户,规则,首个触发事件ID) 确定性派生，保证相同输入重放出相同 ID。
// 用两路不同种子的 FNV-1a 64 位拼接成 16 字节十六进制，降低单路碰撞概率。
func alertID(tenant, ruleID, firstEventID string) string {
	h1 := fnv.New64a()
	h2 := fnv.New64() // 第二路使用不同算法作为差异化"种子"
	writeIDInput(h1, tenant, ruleID, firstEventID)
	writeIDInput(h2, tenant, ruleID, firstEventID)
	buf := make([]byte, 16)
	binary.BigEndian.PutUint64(buf[0:8], h1.Sum64())
	binary.BigEndian.PutUint64(buf[8:16], h2.Sum64())
	const hex = "0123456789abcdef"
	out := make([]byte, 32)
	for i, b := range buf {
		out[2*i] = hex[b>>4]
		out[2*i+1] = hex[b&0x0f]
	}
	return "alrt-" + string(out)
}

func writeIDInput(h interface{ Write([]byte) (int, error) }, parts ...string) {
	sep := []byte{0}
	for i, p := range parts {
		if i > 0 {
			h.Write(sep)
		}
		h.Write([]byte(p))
	}
}
