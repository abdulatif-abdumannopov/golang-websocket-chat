package crypt_tools

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"

	"golang.org/x/crypto/argon2"
)

// deriveKeyArgon2id генерирует 32-байтовый ключ с помощью Argon2id.
// Параметры:
//   - password: пароль в виде байтового слайса.
//   - salt: соль длиной 16 байт.
//
// Используются следующие параметры Argon2id:
//   - time (iterations): 1
//   - memory: 64 МБ (64*1024 КБ)
//   - threads: 4
//   - key length: 32 байта.
func deriveKeyArgon2id(password, salt []byte) []byte {
	return argon2.IDKey(password, salt, 1, 64*1024, 4, 32)
}

// EncryptAES использует AES-256-GCM для шифрования текста.
// Для деривации ключа применяется Argon2id.
func EncryptAES(plainText, password string) (string, error) {
	// Генерация соли (16 байт)
	salt := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return "", err
	}
	// Получение ключа через Argon2id
	key := deriveKeyArgon2id([]byte(password), salt)

	// Создание AES-блока
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	// Создание GCM: nonce рекомендуется 12 байт
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonce := make([]byte, aesGCM.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}

	// Шифрование данных
	cipherText := aesGCM.Seal(nil, nonce, []byte(plainText), nil)
	// Объединение соли, nonce и зашифрованных данных для последующей расшифровки
	result := append(salt, append(nonce, cipherText...)...)
	// Кодирование результата в Base64
	return base64.StdEncoding.EncodeToString(result), nil
}

// DecryptAES расшифровывает текст, зашифрованный функцией encryptAES.
func DecryptAES(cipherTextB64, password string) (string, error) {
	// Декодирование Base64
	data, err := base64.StdEncoding.DecodeString(cipherTextB64)
	if err != nil {
		return "", err
	}

	// Проверка минимальной длины данных: 16 байт соли + размер nonce
	if len(data) < 16 {
		return "", fmt.Errorf("недопустимая длина данных")
	}

	// Извлечение соли
	salt := data[:16]
	// Извлечение nonce: размер зависит от GCM, обычно 12 байт
	// Для определения размера нужно создать временный блок
	key := deriveKeyArgon2id([]byte(password), salt)
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonceSize := aesGCM.NonceSize()
	if len(data) < 16+nonceSize {
		return "", fmt.Errorf("недопустимая длина данных")
	}

	nonce := data[16 : 16+nonceSize]
	encryptedData := data[16+nonceSize:]

	// Расшифровка
	plainText, err := aesGCM.Open(nil, nonce, encryptedData, nil)
	if err != nil {
		return "", err
	}

	return string(plainText), nil
}
