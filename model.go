package BasicTypeAes

type Data struct {
	CipherData []byte
	DataType   int
	PlainData  []byte
	Version    []byte
	Key        []byte
	KeyIndex   int
}

const (
	StringData  = 1
	Int64Data   = 2
	BytesData   = 3
	Float64Data = 4
)

const SumKey = 1
const VersionLen = 5
