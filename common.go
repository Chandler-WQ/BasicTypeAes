package BasicTypeAes

import (
	"math/rand"
	"strconv"
)

func StringToBytes(str string) []byte {
	return []byte(str)
}

func Int64StrToBytes(num int64) []byte {
	str := strconv.FormatInt(num, 10)
	return StringToBytes(str)
}

func Float64StrToBytes(num float64) []byte {
	str := strconv.FormatFloat(num, 'E', -1, 64)
	return StringToBytes(str)
}

var AesKeys []string

func init() {
	AesKeys = []string{"12345678abcdefgh"}
	if len(AesKeys) != SumKey {
		panic("init aes key error")
	}
}

func GetRandomKeyIndex() int32 {
	return int32(rand.Intn(100) % SumKey)
}

func getAesKey(keyIndex int32) []byte {
	if int(keyIndex) > len(AesKeys) {
		return []byte(AesKeys[0])
	}
	return []byte(AesKeys[keyIndex])
}

func getRandKey() ([]byte, int32) {
	keyIndex := GetRandomKeyIndex()
	key := getAesKey(keyIndex)
	return key, keyIndex

}
