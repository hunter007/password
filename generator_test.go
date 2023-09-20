package password

import (
	"fmt"
	"testing"
)

func TestGenerate(t *testing.T) {
	t.Run("Generate", func(t *testing.T) {
		p, err := Generate(12, 4, 2, 1)
		if err != nil {
			t.Errorf("err: %s", err)
		}
		fmt.Printf("password=%s\n", p)
	})

	t.Run("utf8", func(t *testing.T) {
		c := Config{
			UpperLetters: "壹贰叁肆伍陆柒捌玖拾",
			LowerLetters: "一二三四五六七八九十",
			Digits:       "①②③④⑤⑥⑦⑧⑨⑩0️⃣✅",
			Symbols:      "😭😁😄😞👏🏻🙋🏻‍♀️😴🔥",
		}
		g := NewGenerator(c)
		p, err := g.Generate(12, 4, 2, 1)
		if err != nil {
			t.Errorf("err: %s", err)
		}
		fmt.Printf("utf8 password=%s\n", p)
	})

	t.Run("error", func(t *testing.T) {
		_, err := Generate(12, 4, 18, 1)
		if err == nil {
			t.Error("should not be nil")
			return
		}
	})
}
