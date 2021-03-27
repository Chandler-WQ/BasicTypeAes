package BasicTypeAes

type Data struct {
	CipherData []byte
	DataType   int32
	PlainData  []byte
	Version    []byte
	KeyIndex   int32
}

const (
	StringData  = 1
	Int64Data   = 2
	BytesData   = 3
	Float64Data = 4
)

const SumKey = 1
const VersionLen = 5

var Version = []byte("1.0.0")
