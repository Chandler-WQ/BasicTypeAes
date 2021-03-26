package BasicTypeAes

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"strconv"
)

type AesController interface {
	Encrypt(plainData interface{}) (string, error)
	DecryptInt64(cipherStr string) (int64, error)
	DecryptFloat64(cipherStr string) (float64, error)
	DecryptString(cipherStr string) (string, error)
	DecryptBytes(cipherStr string) ([]byte, error)
}

var _ AesController = (*Data)(nil)

func (data *Data) Encrypt(plainData interface{}) (string, error) {
	if data.CheckNil() {
		return "", errors.New("the data is nil")
	}
	key, index := GetRandKey()
	data.Key = key
	data.KeyIndex = index

	switch plainData.(type) {
	case int64:
		num, _ := plainData.(int64)
		plainBytes := Int64StrToBytes(num)
		data.PlainData = plainBytes
		data.DataType = Int64Data
	case []byte:
		num, _ := plainData.([]byte)
		data.PlainData = num
		data.DataType = BytesData
	case float64:
		num, _ := plainData.(float64)
		plainBytes := Float64StrToBytes(num)
		data.PlainData = plainBytes
		data.DataType = Float64Data
	case string:
		str, _ := plainData.(string)
		plainBytes := StringToBytes(str)
		data.PlainData = plainBytes
		data.DataType = StringData
	default:
		return "", errors.New("this type is not currently supported")
	}

	return data.encrypt()
}

func (data *Data) modelToCipherStr() string {
	var buffer bytes.Buffer
	dataTypeBytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(dataTypeBytes, uint32(data.DataType))

	keyIndexBytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(dataTypeBytes, uint32(data.KeyIndex))

	buffer.Write(data.Version)
	buffer.Write(dataTypeBytes)
	buffer.Write(keyIndexBytes)
	buffer.Write(data.CipherData)
	encodeStr := base64.RawURLEncoding.EncodeToString(buffer.Bytes())
	return encodeStr
}

func (data *Data) encrypt() (string, error) {
	if data.CheckNil() {
		return "", errors.New("the data is nil")
	}
	var err error
	data.CipherData, err = AesEncrypt(data.PlainData, data.Key)
	if err != nil {
		return "", err
	}
	encodeStr := data.modelToCipherStr()
	return encodeStr, nil
}

func (data *Data) cipherStrToModel(cipherStr string) error {
	var cipherBytes []byte
	var err error
	cipherBytes, err = base64.RawURLEncoding.DecodeString(cipherStr)
	if err != nil {
		return err
	}
	if len(cipherStr) < VersionLen+8 {
		return errors.New("the length of cipherStr is error")
	}

	data.Version = cipherBytes[:VersionLen]
	data.DataType = int(binary.LittleEndian.Uint32(cipherBytes[VersionLen : VersionLen+4]))
	data.KeyIndex = int(binary.LittleEndian.Uint32(cipherBytes[VersionLen+4 : VersionLen+8]))
	data.CipherData = cipherBytes[VersionLen+8:]
	data.Key = GetAesKey(data.KeyIndex)
	data.PlainData, err = AesDecrypt(data.CipherData, data.Key)
	if err != nil {
		return err
	}
	return nil
}

func (data *Data) decrypt(cipherStr string) ([]byte, error) {
	if data.CheckNil() {
		return nil, errors.New("the data is nil")
	}
	key := GetAesKey(data.KeyIndex)
	data.Key = key

	var err error
	err = data.cipherStrToModel(cipherStr)
	if err != nil {
		return nil, err
	}
	return data.PlainData, nil
}

func (data *Data) DecryptInt64(cipherStr string) (int64, error) {
	plainData, err := data.decrypt(cipherStr)
	if err != nil {
		return 0, err
	}
	if data.DataType != Int64Data {
		return 0, errors.New("conversion type mismatch")
	}
	return strconv.ParseInt(string(plainData), 10, 64)
}

func (data *Data) DecryptFloat64(cipherStr string) (float64, error) {
	plainData, err := data.decrypt(cipherStr)
	if err != nil {
		return 0.0, err
	}
	if data.DataType != Float64Data {
		return 0, errors.New("conversion type mismatch")
	}
	return strconv.ParseFloat(string(plainData), 64)
}

func (data *Data) DecryptString(cipherStr string) (string, error) {
	plainData, err := data.decrypt(cipherStr)
	if err != nil {
		return "", err
	}
	if data.DataType != StringData {
		return "", errors.New("conversion type mismatch")
	}
	return string(plainData), err
}

func (data *Data) DecryptBytes(cipherStr string) ([]byte, error) {
	plainData, err := data.decrypt(cipherStr)
	if err != nil {
		return nil, err
	}
	if data.DataType != StringData {
		return nil, errors.New("conversion type mismatch")
	}
	return plainData, err
}

func (data *Data) CheckNil() bool {
	return data == nil
}
