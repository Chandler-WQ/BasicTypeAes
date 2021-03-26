package BasicTypeAes

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"errors"
)

//填充明文
func PKCS5Padding(plaintext []byte, blockSize int) []byte {
	padding := blockSize - len(plaintext)%blockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(plaintext, padtext...)
}

//去除填充数据
func PKCS5UnPadding(origData []byte) []byte {
	length := len(origData)
	unpadding := int(origData[length-1])
	return origData[:(length - unpadding)]
}

//AES加密
func AesEncrypt(origData, key []byte) ([]byte, error) {
	if len(origData) == 0 {
		return nil, errors.New("the length of origData is error")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	//AES分组长度为128位，所以blockSize=16，单位字节
	origData = PKCS5Padding(origData, block.BlockSize())
	blockMode := cipher.NewCBCEncrypter(block, key[:block.BlockSize()]) //初始向量的长度必须等于块block的长度16字节

	crypted := make([]byte, len(origData))
	blockMode.CryptBlocks(crypted, origData)

	return crypted, nil
}

//AES解密
func AesDecrypt(crypted, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	//AES分组长度为128位，所以blockSize=16，单位字节

	if len(crypted) < block.BlockSize() || len(crypted)%block.BlockSize() != 0 {
		return nil, errors.New("the length of data is error")
	}

	blockMode := cipher.NewCBCDecrypter(block, key[:block.BlockSize()]) //初始向量的长度必须等于块block的长度16字节

	origData := make([]byte, len(crypted))
	blockMode.CryptBlocks(origData, crypted)
	origData = PKCS5UnPadding(origData)
	return origData, nil
}
