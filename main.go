package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"crypto/md5"
	"crypto/rand"
	"crypto/rc4"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"strings"
	"unicode/utf16"
	"unicode/utf8"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/widget"
	"github.com/zmap/rc2"
)

func main() {
	fmt.Println("[!] Running...")
	a := app.New()
	w := a.NewWindow("Text converter")
	w.Resize(fyne.NewSize(500, 470))

	labelInput := widget.NewLabel("Input")
	textArea := widget.NewMultiLineEntry()
	textArea.Wrapping = fyne.TextWrapWord // Disable horizontal scroll by wrapping text

	btnOpenFile := widget.NewButton("Open file", func() {
		dialog.NewFileOpen(func(reader fyne.URIReadCloser, err error) {
			if err != nil {
				dialog.ShowError(err, w)
				return
			}
			if reader == nil {
				return
			}
			defer reader.Close()

			data, err := io.ReadAll(reader)
			if err != nil {
				dialog.ShowError(err, w)
				return
			}
			textArea.SetText(string(data))
		}, w).Show()
	})

	resultArea := widget.NewMultiLineEntry()
	resultArea.Wrapping = fyne.TextWrapWord // Disable horizontal scroll by wrapping text
	labelOutput := widget.NewLabel("Output")

	checkbox := widget.NewCheck("Decode/Unescape mode", func(b bool) {
		if b {
			fmt.Println("decode mode: True")
		} else {
			fmt.Println("decode mode: False")
		}
	})

	singleLineInput := widget.NewEntry()
	singleLineInput.SetPlaceHolder("Enter key here")
	singleLineInput.Disable() // Disabled by default

	var labelSingleInput = widget.NewLabel("Key for XOR/RC4/RC2/DES/3DES/AES")
	combo := widget.NewSelect([]string{
		"ROT13", "ROT47", "Base64", "Base64 (UTF-16LE)", "Hexadecimal", "JSON", "XML", "URL", "XOR", "RC4", "RC2", "DES", "3DES", "AES", "MD5", "SHA1", "SHA224", "SHA256", "SHA512",
	}, func(value string) {
		fmt.Println("Selected:", value)
		switch value {
		case "XOR", "RC4", "RC2", "DES", "3DES", "AES":
			singleLineInput.Enable()
		default:
			singleLineInput.Disable()
		}
	})

	btnConvert := widget.NewButton("Transmute", func() {
		fmt.Println("Button clicked!")
		result := TextConverter(combo.Selected, textArea.Text, singleLineInput.Text, checkbox.Checked)
		resultArea.SetText(result)
	})

	// Add a button to copy the result to the clipboard
	btnCopy := widget.NewButton("Copy Result", func() {
		result := resultArea.Text
		w.Clipboard().SetContent(result)
	})

	content := container.NewVBox(
		labelInput, textArea, btnOpenFile, combo, labelSingleInput, singleLineInput, checkbox, btnConvert, labelOutput, resultArea, btnCopy,
	)
	w.SetContent(content)
	w.ShowAndRun()
}

func TextConverter(option string, input string, key string, is_decode bool) string {
	conversionMap := map[string]func(string, string, bool) (string, error){
		"ROT13": func(input, key string, is_decode bool) (string, error) {
			return Rot13(input), nil
		},
		"ROT47": func(input, key string, is_decode bool) (string, error) {
			return Rot47(input), nil
		},
		"Base64": func(input, key string, is_decode bool) (string, error) {
			return base64.StdEncoding.EncodeToString([]byte(input)), nil
		},
		"Base64 (UTF-16LE)": func(input, key string, is_decode bool) (string, error) {
			if is_decode {
				output, err := DecodeBase64UTF16LE(input)
				return output, err
			}
			return EncodeBase64UTF16LE(input), nil
		},
		"Hexadecimal": func(input, key string, is_decode bool) (string, error) {
			if is_decode {
				output, err := HexDecode(input)
				return output, err
			}
			return HexEncode(input), nil
		},
		"JSON": func(input, key string, is_decode bool) (string, error) {
			if is_decode {
				output, err := JSONUnescape(input)
				return output, err
			}
			return JsonEscape(input), nil
		},
		"XML": func(input, key string, is_decode bool) (string, error) {
			if is_decode {
				return XmlUnescape(input), nil
			}
			return XmlEscape(input), nil
		},
		"URL": func(input, key string, is_decode bool) (string, error) {
			if is_decode {
				output, err := UrlDecode(input)
				return output, err
			}
			return UrlEncode(input), nil
		},
		"XOR": func(input, key string, is_decode bool) (string, error) {
			return XorEncryptDecrypt(input, key), nil
		},
		"RC4": func(input, key string, is_decode bool) (string, error) {
			output, err := Rc4EncryptDecrypt(input, key)
			return string(output), err
		},
		"RC2": func(input, key string, is_decode bool) (string, error) {
			if is_decode {
				output, err := Rc2Decrypt(input, key)
				return string(output), err
			}
			output, err := Rc2Encrypt(input, key)
			return output, err
		},
		"DES": func(input, key string, is_decode bool) (string, error) {
			if is_decode {
				output, err := DesDecrypt(input, key)
				return string(output), err
			}
			output, err := DesEncrypt(input, key)
			return output, err
		},
		"3DES": func(input, key string, is_decode bool) (string, error) {
			if is_decode {
				output, err := TripleDESDecrypt(input, key)
				return string(output), err
			}
			output, err := TripleDESEncrypt(input, key)
			return output, err
		},
		"AES": func(input, key string, is_decode bool) (string, error) {
			if is_decode {
				output, err := AesDecrypt(input, key)
				return string(output), err
			}
			output, err := AesEncrypt(input, key)
			return output, err
		},
		"MD5": func(input, key string, is_decode bool) (string, error) {
			return Md5Hash(input), nil
		},
		"SHA1": func(input, key string, is_decode bool) (string, error) {
			return Sha1Hash(input), nil
		},
		"SHA224": func(input, key string, is_decode bool) (string, error) {
			return Sha224Hash(input), nil
		},
		"SHA256": func(input, key string, is_decode bool) (string, error) {
			return Sha256Hash(input), nil
		},
		"SHA512": func(input, key string, is_decode bool) (string, error) {
			return Sha512Hash(input), nil
		},
	}

	if converter, found := conversionMap[option]; found {
		output, err := converter(input, key, is_decode)
		if err != nil {
			return err.Error()
		}
		return output
	}

	return "Invalid option"
}

func Rot13(input string) string {
	var result []rune
	for _, char := range input {
		switch {
		case char >= 'a' && char <= 'z':
			result = append(result, 'a'+(char-'a'+13)%26)
		case char >= 'A' && char <= 'Z':
			result = append(result, 'A'+(char-'A'+13)%26)
		default:
			result = append(result, char)
		}
	}
	return string(result)
}

func Rot47(input string) string {
	var result []rune
	for _, char := range input {
		if char >= 33 && char <= 126 {
			result = append(result, 33+((char+14)%94))
		} else {
			result = append(result, char)
		}
	}
	return string(result)
}

func EncodeBase64UTF16LE(input string) string {
	utf16LEBytes := utf8ToUtf16LEBytes(input)
	base64Encoded := base64.StdEncoding.EncodeToString(utf16LEBytes)
	return base64Encoded
}

func DecodeBase64UTF16LE(input string) (string, error) {
	utf16LEBytes, err := Base64ToUtf16LEBytes(input)
	if err != nil {
		return "", err
	}
	utf8String, err := Utf16LEBytesToUtf8(utf16LEBytes)
	if err != nil {
		return "", err
	}
	return utf8String, nil
}

func JsonEscape(input string) string {
	escaped, _ := json.Marshal(input)
	return string(escaped)
}

func JSONUnescape(jsonStr string) (string, error) {
	var unescapedStr string
	err := json.Unmarshal([]byte(jsonStr), &unescapedStr)
	if err != nil {
		return "", err
	}
	return unescapedStr, nil
}

func XmlEscape(input string) string {
	replacer := strings.NewReplacer(
		"&", "&amp;",
		"<", "&lt;",
		">", "&gt;",
		"\"", "&quot;",
		"'", "&apos;",
	)
	return replacer.Replace(input)
}

func XmlUnescape(input string) string {
	replacer := strings.NewReplacer(
		"&amp;", "&",
		"&lt;", "<",
		"&gt;", ">",
		"&quot;", "\"",
		"&apos;", "'",
	)
	return replacer.Replace(input)
}

func UrlEncode(input string) string {
	return url.QueryEscape(input)
}

func UrlDecode(input string) (string, error) {
	return url.QueryUnescape(input)
}

func XorEncryptDecrypt(input, key string) string {
	output := make([]byte, len(input))

	for i := 0; i < len(input); i++ {
		output[i] = input[i] ^ key[i%len(key)]
	}

	return string(output)
}

func Rc2Encrypt(plaintext, key string) (string, error) {
	keyBytes := []byte(key)
	plaintextBytes := []byte(plaintext)
	block, err := rc2.NewCipher(keyBytes)
	if err != nil {
		return "", err
	}

	if len(plaintextBytes)%block.BlockSize() != 0 {
		return "", fmt.Errorf("plaintext is not a multiple of the block size")
	}

	ciphertext := make([]byte, len(plaintextBytes))
	mode := NewECBEncrypter(block)
	mode.CryptBlocks(ciphertext, plaintextBytes)

	return hex.EncodeToString(ciphertext), nil
}

func Rc2Decrypt(ciphertextHex, key string) (string, error) {
	keyBytes := []byte(key)
	ciphertext, err := hex.DecodeString(ciphertextHex)
	if err != nil {
		return "", err
	}

	block, err := rc2.NewCipher(keyBytes)
	if err != nil {
		return "", err
	}

	if len(ciphertext)%block.BlockSize() != 0 {
		return "", fmt.Errorf("ciphertext is not a multiple of the block size")
	}

	plaintext := make([]byte, len(ciphertext))
	mode := NewECBDecrypter(block)
	mode.CryptBlocks(plaintext, ciphertext)

	return string(plaintext), nil
}

func Rc4EncryptDecrypt(input, key string) (string, error) {
	keyBytes := []byte(key)
	inputBytes := []byte(input)

	cipher, err := rc4.NewCipher(keyBytes)
	if err != nil {
		return "", err
	}
	output := make([]byte, len(inputBytes))
	cipher.XORKeyStream(output, inputBytes)

	return hex.EncodeToString(output), nil
}

func DesEncrypt(plaintext, key string) (string, error) {
	keyBytes := []byte(key)
	plaintextBytes := []byte(plaintext)

	block, err := des.NewCipher(keyBytes)
	if err != nil {
		return "", err
	}

	// Create a new IV
	iv := make([]byte, block.BlockSize())
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return "", err
	}

	// Pad plaintext to be a multiple of block size
	padding := block.BlockSize() - len(plaintextBytes)%block.BlockSize()
	paddedText := append(plaintextBytes, make([]byte, padding)...)

	// Encrypt
	ciphertext := make([]byte, len(paddedText))
	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext, paddedText)

	// Prepend IV to ciphertext
	ciphertext = append(iv, ciphertext...)

	return hex.EncodeToString(ciphertext), nil
}

func DesDecrypt(ctHex, key string) (string, error) {
	keyBytes := []byte(key)
	ciphertext, err := hex.DecodeString(ctHex)
	if err != nil {
		return "", err
	}

	block, err := des.NewCipher(keyBytes)
	if err != nil {
		return "", err
	}

	iv := ciphertext[:block.BlockSize()]
	ciphertext = ciphertext[block.BlockSize():]

	if len(ciphertext)%block.BlockSize() != 0 {
		return "", fmt.Errorf("ciphertext is not a multiple of the block size")
	}

	plaintext := make([]byte, len(ciphertext))
	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(plaintext, ciphertext)

	// Remove padding
	paddingLength := int(plaintext[len(plaintext)-1])
	plaintext = plaintext[:len(plaintext)-paddingLength]

	return string(plaintext), nil
}

func TripleDESEncrypt(plaintext, key string) (string, error) {
	keyBytes := []byte(key)
	plaintextBytes := []byte(plaintext)

	block, err := des.NewTripleDESCipher(keyBytes)
	if err != nil {
		return "", err
	}

	// Create a new IV
	iv := make([]byte, block.BlockSize())
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return "", err
	}

	// Pad plaintext to be a multiple of block size
	padding := block.BlockSize() - len(plaintextBytes)%block.BlockSize()
	paddedText := append(plaintextBytes, make([]byte, padding)...)

	// Encrypt
	ciphertext := make([]byte, len(paddedText))
	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext, paddedText)

	// Prepend IV to ciphertext
	ciphertext = append(iv, ciphertext...)

	return hex.EncodeToString(ciphertext), nil
}

func TripleDESDecrypt(ctHex, key string) (string, error) {
	keyBytes := []byte(key)
	ciphertext, err := hex.DecodeString(ctHex)
	if err != nil {
		return "", err
	}

	block, err := des.NewTripleDESCipher(keyBytes)
	if err != nil {
		return "", err
	}

	iv := ciphertext[:block.BlockSize()]
	ciphertext = ciphertext[block.BlockSize():]

	if len(ciphertext)%block.BlockSize() != 0 {
		return "", fmt.Errorf("ciphertext is not a multiple of the block size")
	}

	plaintext := make([]byte, len(ciphertext))
	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(plaintext, ciphertext)

	// Remove padding
	plaintext = plaintext[:len(plaintext)-int(plaintext[len(plaintext)-1])]

	return string(plaintext), nil
}

func AesEncrypt(plaintext, key string) (string, error) {
	keyBytes := []byte(key)
	plaintextBytes := []byte(plaintext)

	block, err := aes.NewCipher(keyBytes)
	if err != nil {
		return "", err
	}

	// Create a new IV
	iv := make([]byte, aes.BlockSize)
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return "", err
	}

	// Pad plaintext to be a multiple of block size
	padding := aes.BlockSize - len(plaintextBytes)%aes.BlockSize
	paddedText := append(plaintextBytes, make([]byte, padding)...)

	// Encrypt
	ciphertext := make([]byte, len(paddedText))
	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext, paddedText)

	// Prepend IV to ciphertext
	ciphertext = append(iv, ciphertext...)

	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

func AesDecrypt(ctBase64, key string) (string, error) {
	keyBytes := []byte(key)
	ciphertext, err := base64.StdEncoding.DecodeString(ctBase64)
	if err != nil {
		return "", err
	}

	block, err := aes.NewCipher(keyBytes)
	if err != nil {
		return "", err
	}

	iv := ciphertext[:aes.BlockSize]
	ciphertext = ciphertext[aes.BlockSize:]

	if len(ciphertext)%aes.BlockSize != 0 {
		return "", fmt.Errorf("ciphertext is not a multiple of the block size")
	}

	plaintext := make([]byte, len(ciphertext))
	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(plaintext, ciphertext)

	// Remove padding
	paddingLength := int(plaintext[len(plaintext)-1])
	plaintext = plaintext[:len(plaintext)-paddingLength]

	return string(plaintext), nil
}

func Md5Hash(input string) string {
	hasher := md5.New()
	hasher.Write([]byte(input))
	return hex.EncodeToString(hasher.Sum(nil))
}

func Sha1Hash(input string) string {
	hasher := sha1.New()
	hasher.Write([]byte(input))
	return hex.EncodeToString(hasher.Sum(nil))
}

func Sha224Hash(input string) string {
	hasher := sha256.New224()
	hasher.Write([]byte(input))
	return hex.EncodeToString(hasher.Sum(nil))
}

func Sha256Hash(input string) string {
	hasher := sha256.New()
	hasher.Write([]byte(input))
	return hex.EncodeToString(hasher.Sum(nil))
}

func Sha384Hash(input string) string {
	hasher := sha512.New384()
	hasher.Write([]byte(input))
	return hex.EncodeToString(hasher.Sum(nil))
}

func Sha512Hash(input string) string {
	hasher := sha512.New()
	hasher.Write([]byte(input))
	return hex.EncodeToString(hasher.Sum(nil))
}

func HexEncode(input string) string {
	return hex.EncodeToString([]byte(input))
}

func HexDecode(input string) (string, error) {
	bytes, err := hex.DecodeString(input)
	if err != nil {
		return "", err
	}
	return string(bytes), nil
}

func utf8ToUtf16LEBytes(s string) []byte {
	utf16Encoded := utf16.Encode([]rune(s))
	bytes := make([]byte, len(utf16Encoded)*2)
	for i, v := range utf16Encoded {
		bytes[i*2] = byte(v)
		bytes[i*2+1] = byte(v >> 8)
	}
	return bytes
}

func Base64ToUtf16LEBytes(s string) ([]byte, error) {
	utf16LEBytes, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return nil, err
	}
	return utf16LEBytes, nil
}

func Utf16LEBytesToUtf8(b []byte) (string, error) {
	if len(b)%2 != 0 {
		return "", fmt.Errorf("invalid UTF-16LE byte slice length")
	}

	utf16Data := make([]uint16, len(b)/2)
	for i := 0; i < len(utf16Data); i++ {
		utf16Data[i] = uint16(b[i*2]) | uint16(b[i*2+1])<<8
	}

	runes := utf16.Decode(utf16Data)
	utf8Bytes := make([]byte, 0, len(runes)*utf8.UTFMax)
	for _, r := range runes {
		utf8Bytes = append(utf8Bytes, string(r)...)
	}

	return string(utf8Bytes), nil
}

type ecb struct {
	b         cipher.Block
	blockSize int
}

func newECB(b cipher.Block) *ecb {
	return &ecb{
		b:         b,
		blockSize: b.BlockSize(),
	}
}

type ecbEncrypter ecb

func NewECBEncrypter(b cipher.Block) cipher.BlockMode {
	return (*ecbEncrypter)(newECB(b))
}

func (x *ecbEncrypter) BlockSize() int { return x.blockSize }

func (x *ecbEncrypter) CryptBlocks(dst, src []byte) {
	if len(src)%x.blockSize != 0 {
		panic("crypto/cipher: input not full blocks")
	}
	if len(dst) < len(src) {
		panic("crypto/cipher: output smaller than input")
	}
	for len(src) > 0 {
		x.b.Encrypt(dst, src[:x.blockSize])
		src = src[x.blockSize:]
		dst = dst[x.blockSize:]
	}
}

type ecbDecrypter ecb

func NewECBDecrypter(b cipher.Block) cipher.BlockMode {
	return (*ecbDecrypter)(newECB(b))
}

func (x *ecbDecrypter) BlockSize() int { return x.blockSize }

func (x *ecbDecrypter) CryptBlocks(dst, src []byte) {
	if len(src)%x.blockSize != 0 {
		panic("crypto/cipher: input not full blocks")
	}
	if len(dst) < len(src) {
		panic("crypto/cipher: output smaller than input")
	}
	for len(src) > 0 {
		x.b.Decrypt(dst, src[:x.blockSize])
		src = src[x.blockSize:]
		dst = dst[x.blockSize:]
	}
}
