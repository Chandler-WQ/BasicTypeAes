# BasicTypeAes
Aes加解密适用于golang基础类型的封装


使用方法
```cgo
func TestAesEncrypt(t *testing.T) {
	data := &Data{}
	var int64PlainData int64 = 100
	var stringPlainData string = "test example"
	var bytesPlainData []byte = []byte("sdagasdaa")
	var float64PlainData float64 = 123.456
	int64CipherData, err := data.Encrypt(int64PlainData)
	assert.Nil(t, err)
	assert.Equal(t, int(data.DataType), Int64Data)
	t.Logf("the int64CipherData is %v", int64CipherData)

	stringCipherData, err := data.Encrypt(stringPlainData)
	assert.Nil(t, err)
	assert.Equal(t, int(data.DataType), StringData)
	t.Logf("the stringCipherData is %v", stringCipherData)

	bytesCipherData, err := data.Encrypt(bytesPlainData)
	assert.Nil(t, err)
	assert.Equal(t, int(data.DataType), BytesData)
	t.Logf("the bytesCipherData is %v", bytesCipherData)

	float64CipherData, err := data.Encrypt(float64PlainData)
	assert.Nil(t, err)
	assert.Equal(t, int(data.DataType), Float64Data)
	t.Logf("the float64CipherData is %v", float64CipherData)

	num, err := data.DecryptInt64(int64CipherData)
	assert.Nil(t, err)
	assert.Equal(t, int(data.DataType), Int64Data)
	assert.Equal(t, num, int64PlainData)
	t.Logf("the num is %v", num)

	str, err := data.DecryptString(stringCipherData)
	assert.Nil(t, err)
	assert.Equal(t, int(data.DataType), StringData)
	assert.Equal(t, str, stringPlainData)
	t.Logf("the str is %v", str)

	bytes, err := data.DecryptBytes(bytesCipherData)
	assert.Nil(t, err)
	assert.Equal(t, int(data.DataType), BytesData)
	assert.Equal(t, bytes, bytesPlainData)
	t.Logf("the bytes is %v", string(bytes))

	float64Num, err := data.DecryptFloat64(float64CipherData)
	assert.Nil(t, err)
	assert.Equal(t, int(data.DataType), Float64Data)
	assert.Equal(t, float64Num, float64PlainData)
	t.Logf("the float64Num is %v", float64Num)

}

```

测试输出：
```cgo
=== RUN   TestAesEncrypt
    TestAesEncrypt: controller_test.go:18: the int64CipherData is MS4wLjACAAAAAAAAAJL8WssDe6xNtrXRKnE8DgI
    TestAesEncrypt: controller_test.go:23: the stringCipherData is MS4wLjABAAAAAAAAAAzmsPvmdGv05Zr-r2UVOes
    TestAesEncrypt: controller_test.go:28: the bytesCipherData is MS4wLjADAAAAAAAAANWwL8Q6iJrjMosDa75d1yg
    TestAesEncrypt: controller_test.go:33: the float64CipherData is MS4wLjAEAAAAAAAAABVq-xWKB68hxLlHIAjVn5Q
    TestAesEncrypt: controller_test.go:39: the num is 100
    TestAesEncrypt: controller_test.go:45: the str is test example
    TestAesEncrypt: controller_test.go:51: the bytes is sdagasdaa
    TestAesEncrypt: controller_test.go:57: the float64Num is 123.456
--- PASS: TestAesEncrypt (0.00s)
PASS
```
