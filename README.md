## password - A password feature library wrote in golang.

[![Test](https://github.com/hunter007/password/workflows/Unittest/badge.svg)](https://github.com/hunter007/password/actions?query=workflow%3AUnitTest)
[![Go Report Card](https://goreportcard.com/badge/github.com/hunter007/password)](https://goreportcard.com/report/github.com/hunter007/password)
![GitHub go.mod Go version](https://img.shields.io/github/go-mod/go-version/hunter007/password)
[![codecov](https://codecov.io/gh/hunter007/password/branch/main/graph/badge.svg)](https://codecov.io/gh/hunter007/password)
[![Go Reference](https://pkg.go.dev/badge/github.com/hunter007/password.svg)](https://pkg.go.dev/github.com/hunter007/password)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-green.svg)](https://opensource.org/license/apache-2-0)


## Highlights

* Validate password according options
* Validate whether a password is common
* Generate password according options
* Encode & decode password according options
* Verify password according options


## Install

```shell
go get github.com/hunter007/password
```

## Usage

#### 0. Generate password

```go
// 1. generate password via default config
p, _ := password.Generate(12, 4, 2, 1)

// 2. make a custom config. Any utf8 char is supported.
c := Config{
    UpperLetters: "壹贰叁肆伍陆柒捌玖拾",
    LowerLetters: "一二三四五六七八九十",
    Digits:       "①②③④⑤⑥⑦⑧⑨⑩0️⃣✅",
    Symbols:      "😭😁😄😞👏🏻🙋🏻‍♀️😴🔥",
}
g := NewGenerator(c)
p, _ := g.Generate(16, 4, 3, 0)
```

#### 1. Validate password

```go
// 1. setup ValidatorOption
voption := &ValidatorOption{
    MinLength: 6,
    MaxLength: 20,
    CommonPasswords: []string{"123456", "1qasw23ed"},
    RequireDigit: true,
    RequireLetter: true,
    RequirePunctuation: true,
}

// or use map
var voption ValidatorOption
config := map[string]interface{}{
    "min_length":          6,
    "max_length":          20,
    "common_passwords":    []string{"123456", "1qasw23ed"},
    "require_digit":       true,
    "require_letter":      true,
    "require_punctuation": true,
}
b, _ := json.Marshal(config)
err := json.Unmarshal(b, &voption)

// If CommonPasswords or CommonPasswordURL provided, password will be validated as common password.
// http request is sent by method `GET`, and response body will be as plain text, splited by "\n", one password one line.
voption.CommonPasswordURL = "http://xxx.com/pwd"

// don't forget to handle err
validator, _ := password.New(voption)

// 2. validate password
password := "user password"
err := validator.Validate(password)
if err != nil {
    // handle wrong password
}
```

#### 2. Get hasher

Supported algorithm:

- argon2id
- bcrypt
- bcrypt_sha256
- md5
- unsalted_md5
- pbkdf2_sha1
- pbkdf2_sha256
- sha1
- scrypt

```go
// have a HasherOption
hoption := &HasherOption{
    Algorithm: "pbkdf2_sha256",
    Salt: "app salt",
    Iterations: 10000,
}

// or new HasherOption with map
option = map[string]interface{} {
    "algorithm": "pbkdf2_sha256",
    "secret": "secret",
    "salt": "app salt",
    "iterations": 10000,
}

b, _ := json.Marshal(option)
err := json.Unmarshal(b, &hoption)
if err != nil {
    // handle err
}

hasher, err := password.NewHasher(hoption)
if err != nil {
    // handle err
}
```
#### 3. Encode password

```go
password := "plaintext"
encoded, err := hasher.Encode(password)
if err != nil {
    // handle err
}
```

#### 4. Decode password

```go
pi, err := hasher.Decode(encoded)
if err != nil {
    // handle err
}
// pi contains algorithm, salt, iterations, etc.
```

#### 5. Verify password

```go
if !hasher.Verify(password, encoded) {
    // handle wrong password
}
```
