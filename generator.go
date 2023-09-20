package password

import (
	"crypto/rand"
	"errors"
	"math/big"
	mrand "math/rand"
	"time"
	"unicode/utf8"
)

// Generator provides methods which generates password.
//
// all methods are goroutine-safe.
type Generator interface {
	Generate(length, minDigitLength, minSymbolLength, minUpperLetter uint) (string, error)
	// MustGenerate like `Generate`, generates password.
	//
	// panic if errors occurred
	MustGenerate(length, minDigitLength, minSymbolLength, minUpperLetter uint) string
}

type Config struct {
	// lower letters. any utf8 unicode supported.
	//
	// for example "一二三"
	LowerLetters string
	// upper letters. any utf8 unicode supported.
	//
	// for example "壹贰叁"
	UpperLetters string
	Digits       string
	Symbols      string
	random       RandomFunc
}

func NewGenerator(c Config) Generator {
	return newGenerator(c)
}

type generator struct {
	chars        []rune
	upperLetters []rune
	lowerLetters []rune
	digits       []rune
	symbols      []rune
	random       RandomFunc
}

func (g *generator) Generate(length, minDigitLength, minSymbolLength, minUpperLetter uint) (string, error) {
	if err := check(length, minDigitLength, minSymbolLength, minUpperLetter); err != nil {
		return "", err
	}

	password := make([]rune, 0, length)
	for i, d := 0, len(g.digits); i < int(minDigitLength); i++ {
		password = append(password, g.digits[g.random()%d])
	}

	for i, s := 0, len(g.symbols); i < int(minSymbolLength); i++ {
		password = append(password, g.symbols[g.random()%s])
	}

	for i, u := 0, len(g.upperLetters); i < int(minUpperLetter); i++ {
		password = append(password, g.upperLetters[g.random()%u])
	}

	remain := int(length) - int(minDigitLength) - int(minSymbolLength) - int(minUpperLetter)
	for i, t := 0, len(g.chars); i < remain; i++ {
		password = append(password, g.chars[g.random()%t])
	}

	for i := 0; i < int(length/2); i++ {
		j := g.random() % int(length)
		password[j], password[i] = password[i], password[j]
	}

	return string(password), nil
}

func (g *generator) MustGenerate(length, minDigitLength, minSymbolLength, minUpperLetter uint) string {
	s, err := g.Generate(length, minDigitLength, minSymbolLength, minUpperLetter)
	if err != nil {
		panic(err)
	}
	return s
}

func newGenerator(c Config) Generator {
	lLen := utf8.RuneCountInString(c.LowerLetters)
	uLen := utf8.RuneCountInString(c.UpperLetters)
	dLen := utf8.RuneCountInString(c.Digits)
	sLen := utf8.RuneCountInString(c.Symbols)
	chars := make([]rune, 0, lLen+uLen+dLen+sLen)
	for _, c := range c.LowerLetters {
		chars = append(chars, c)
	}
	for _, c := range c.UpperLetters {
		chars = append(chars, c)
	}
	for _, c := range c.Digits {
		chars = append(chars, c)
	}
	for _, c := range c.Symbols {
		chars = append(chars, c)
	}

	g := &generator{
		chars:        chars,
		lowerLetters: chars[:lLen],
		upperLetters: chars[lLen : lLen+uLen],
		digits:       chars[lLen+uLen : lLen+uLen+dLen],
		symbols:      chars[lLen+uLen+dLen:],
		random:       MathRandom,
	}
	if c.random != nil {
		g.random = c.random
	}
	return g
}

var defaultGenerator Generator

var defaultC = Config{
	LowerLetters: "abcdefghijklmnopqrstuvwxyz",
	UpperLetters: "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
	Digits:       "0123456789",
	Symbols:      "~!@#$%^&*()_+`-={}|[]\\:\"<>?,./",
}

func init() {
	defaultGenerator = newGenerator(defaultC)
}

/*
Generate generates password via default config:

	LowerLetters: abcdefghijklmnopqrstuvwxyz
	UpperLetters: ABCDEFGHIJKLMNOPQRSTUVWXYZ
	Digits: 0123456789
	Symbols: ~!@#$%^&*()_+`-={}|[]\\:\"<>?,./
*/
func Generate(length, minDigitLength, minSymbolLength, minUpperLetter uint) (string, error) {
	return defaultGenerator.Generate(length, minDigitLength, minSymbolLength, minUpperLetter)
}

/*
Generate generates password via default config, panic when error occcurred:

	LowerLetters: abcdefghijklmnopqrstuvwxyz
	UpperLetters: ABCDEFGHIJKLMNOPQRSTUVWXYZ
	Digits: 0123456789
	Symbols: ~!@#$%^&*()_+`-={}|[]\\:\"<>?,./
*/
func MustGenerate(length, minDigitLength, minSymbolLength, minUpperLetter uint) string {
	return defaultGenerator.MustGenerate(length, minDigitLength, minSymbolLength, minUpperLetter)
}

var ErrExceedsLength = errors.New("number of digits, symbols and upper letters must be less than total length")

func check(length, minDigitLength, minSymbolLength, minUpperLetter uint) error {
	if minDigitLength+minSymbolLength+minUpperLetter > length {
		return ErrExceedsLength
	}
	return nil
}

type RandomFunc func() int

// CryptoRandom implemented by crypto/rand
func CryptoRandom() int {
	n, _ := rand.Int(rand.Reader, big.NewInt(10000))
	return int(n.Int64())
}

// MathRandom implemented by math/rand
func MathRandom() int {
	r := mrand.New(mrand.NewSource(time.Now().UnixNano()))
	return int(r.Int63n(10000))
}
