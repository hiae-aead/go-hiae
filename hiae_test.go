package hiae

import (
	"encoding/hex"
	"testing"
)

// Test vector structure
type testVector struct {
	name        string
	key         string
	nonce       string
	ad          string
	msg         string
	expectedCt  string
	expectedTag string
}

// All 10 test vectors from the HiAE specification
var testVectors = []testVector{
	{
		name:        "Test Vector 1 - Empty plaintext, no AD",
		key:         "4b7a9c3ef8d2165a0b3e5f8c9d4a7b1e2c5f8a9d3b6e4c7f0a1d2e5b8c9f4a7d",
		nonce:       "a5b8c2d9e3f4a7b1c8d5e9f2a3b6c7d8",
		ad:          "",
		msg:         "",
		expectedCt:  "",
		expectedTag: "a25049aa37deea054de461d10ce7840b",
	},
	{
		name:        "Test Vector 2 - Single block plaintext, no AD",
		key:         "2f8e4d7c3b9a5e1f8d2c6b4a9f3e7d5c1b8a6f4e3d2c9b5a8f7e6d4c3b2a1f9e",
		nonce:       "7c3e9f5a1d8b4c6f2e9a5d7b3f8c1e4a",
		ad:          "",
		msg:         "55f00fcc339669aa55f00fcc339669aa",
		expectedCt:  "af9bd1865daa6fc351652589abf70bff",
		expectedTag: "ed9e2edc8241c3184fc08972bd8e9952",
	},
	{
		name:        "Test Vector 3 - Empty plaintext with AD",
		key:         "9f3e7d5c4b8a2f1e9d8c7b6a5f4e3d2c1b0a9f8e7d6c5b4a3f2e1d0c9b8a7f6e",
		nonce:       "3d8c7f2a5b9e4c1f8a6d3b7e5c2f9a4d",
		ad:          "394a5b6c7d8e9fb0c1d2e3f405162738495a6b7c8d9eafc0d1e2f30415263748",
		msg:         "",
		expectedCt:  "",
		expectedTag: "7e19c04f68f5af633bf67529cfb5e5f4",
	},
	{
		name:  "Test Vector 4 - Rate-aligned plaintext (256 bytes)",
		key:   "6c8f2d5a9e3b7f4c1d8a5e9f3c7b2d6a4f8e1c9b5d3a7e2f4c8b6d9a1e5f3c7d",
		nonce: "9a5c7e3f1b8d4a6c2e9f5b7d3a8c1e6f",
		ad:    "",
		msg: "ffffffffffffffffffffffffffffffff" +
			"ffffffffffffffffffffffffffffffff" +
			"ffffffffffffffffffffffffffffffff" +
			"ffffffffffffffffffffffffffffffff" +
			"ffffffffffffffffffffffffffffffff" +
			"ffffffffffffffffffffffffffffffff" +
			"ffffffffffffffffffffffffffffffff" +
			"ffffffffffffffffffffffffffffffff" +
			"ffffffffffffffffffffffffffffffff" +
			"ffffffffffffffffffffffffffffffff" +
			"ffffffffffffffffffffffffffffffff" +
			"ffffffffffffffffffffffffffffffff" +
			"ffffffffffffffffffffffffffffffff" +
			"ffffffffffffffffffffffffffffffff" +
			"ffffffffffffffffffffffffffffffff" +
			"ffffffffffffffffffffffffffffffff",
		expectedCt: "cf9f118ccc3ae98998ddaae1a5d1f9a1" +
			"69e4ca3e732baf7178cdd9a353057166" +
			"8fe403e77111eac3da34bf2f25719cea" +
			"09445cc58197b1c6ac490626724e7372" +
			"707cfb60cdba8262f0e33a1ef8adda1f" +
			"2e390a80c58e5c055d9be9bbccdc06ad" +
			"af74f1dcaa372204bf42e5e0e0ac5943" +
			"7a353978298837023f79fac6daa1fe8f" +
			"6bcaaaf060ae2e37ed7b7da0577a7643" +
			"5f0403b8e277b6bc2ea99682f2d0d577" +
			"77fec6d901e0d8fc7cf46bb97336812a" +
			"2d8cfd39053993288cce2c077fce0c6c" +
			"00e99cf919281b261acf86b058164f10" +
			"1d9c24e8f40b4fa0ed60955eeeb4e33f" +
			"f1087519c13db8e287199a7df7e94b0d" +
			"368da9ccf3d2ecebfa46f860348f8e3c",
		expectedTag: "4f42c3042cba3973153673156309dd69",
	},
	{
		name:  "Test Vector 5 - Rate + 1 byte plaintext",
		key:   "3e9d6c5b4a8f7e2d1c9b8a7f6e5d4c3b2a1f0e9d8c7b6a5f4e3d2c1b0a9f8e7d",
		nonce: "6f2e8a5c9b3d7f1e4a8c5b9d3f7e2a6c",
		ad:    "6778899aabbccddeef00112233445566",
		msg: "cc339669aa55f00fcc339669aa55f00f" +
			"cc339669aa55f00fcc339669aa55f00f" +
			"cc339669aa55f00fcc339669aa55f00f" +
			"cc339669aa55f00fcc339669aa55f00f" +
			"cc339669aa55f00fcc339669aa55f00f" +
			"cc339669aa55f00fcc339669aa55f00f" +
			"cc339669aa55f00fcc339669aa55f00f" +
			"cc339669aa55f00fcc339669aa55f00f" +
			"cc339669aa55f00fcc339669aa55f00f" +
			"cc339669aa55f00fcc339669aa55f00f" +
			"cc339669aa55f00fcc339669aa55f00f" +
			"cc339669aa55f00fcc339669aa55f00f" +
			"cc339669aa55f00fcc339669aa55f00f" +
			"cc339669aa55f00fcc339669aa55f00f" +
			"cc339669aa55f00fcc339669aa55f00f" +
			"cc339669aa55f00fcc339669aa55f00f" +
			"cc",
		expectedCt: "522e4cd9b0881809d80e149bb4ed8b8a" +
			"dd70b7257afca6c2bc38e4da11e290cf" +
			"cabd9dd1d4ed8c514482f444f903e42e" +
			"c21a7a605ee37f95a504ec667fabec40" +
			"66eb4521cdaf9c4eb7b62d659ab0a936" +
			"3b145f1120c1b2e589ab9cb893d01be0" +
			"d22182fc7de4932f1e8652b50e4a0d48" +
			"c49a8a1232b201e2e535cd95c15cf0ee" +
			"389b75e372653579c72c4dd1906fd81c" +
			"2b9fc2483fab8b4df5a09d59753b5bd4" +
			"1334be2e5085e349b6e5aac0c555a0a8" +
			"3e94eab974052131f8d451c9d85389a3" +
			"6126f93464e6f93119c6b1bf15b4c0a9" +
			"e6c9beb52e82c846c472f87c15ac49e9" +
			"9d59248ba7e6b97ca04327769d6b8c1f" +
			"751d95dba709fb335183c21476836ea1" +
			"ab",
		expectedTag: "61bac11505dd8bbf55e7fbb7489de7b0",
	},
	{
		name:  "Test Vector 6 - Rate - 1 byte plaintext",
		key:   "8a7f6e5d4c3b2a1f0e9d8c7b6a5f4e3d2c1b0a9f8e7d6c5b4a3f2e1d0c9b8a7f",
		nonce: "4d8b2f6a9c3e7f5d1b8a4c6e9f3d5b7a",
		ad:    "",
		msg: "00000000000000000000000000000000" +
			"00000000000000000000000000000000" +
			"00000000000000000000000000000000" +
			"00000000000000000000000000000000" +
			"00000000000000000000000000000000" +
			"00000000000000000000000000000000" +
			"00000000000000000000000000000000" +
			"00000000000000000000000000000000" +
			"00000000000000000000000000000000" +
			"00000000000000000000000000000000" +
			"00000000000000000000000000000000" +
			"00000000000000000000000000000000" +
			"00000000000000000000000000000000" +
			"00000000000000000000000000000000" +
			"00000000000000000000000000000000" +
			"000000000000000000000000000000",
		expectedCt: "2ba49be54eb675efe446fd597721d4cd" +
			"ca6e01f1a51728a859d8f206d13cdb08" +
			"ba4f0fe78fbbd6885964ed54e9beceed" +
			"1ff306642c4761e67efa7a2620e57128" +
			"15b5e9f066b42e879cd62e7adc2821e5" +
			"08311b88a6ee14bedcbac7ce339994c0" +
			"09bbbadf9444748e4ab9a91acbbc7301" +
			"742dab74aa1be6847ad8e9f08c170359" +
			"b87e0ccd480812aaaf847aff03c2e858" +
			"1c55848c2b50f6c6608540fe82627a2c" +
			"0f5ee37fbe9cdeab5f6c9799702bd303" +
			"2bf733e2108d03247cd20edaa2c322e5" +
			"bf086bfecc4ac97b61096f016c57d5d0" +
			"1c24d398cefd5ae8131c1f51f172ce9c" +
			"6d3b8395d396dcbd70b4af790018796b" +
			"31f0b0ad6198f86e5e1f26e9258492",
		expectedTag: "221dd1b69afb4e0c149e0a058e471a4a",
	},
	{
		name:  "Test Vector 7 - Medium plaintext with AD",
		key:   "5d9c3b7a8f2e6d4c1b9a8f7e6d5c4b3a2f1e0d9c8b7a6f5e4d3c2b1a0f9e8d7c",
		nonce: "8c5a7d3f9b1e6c4a2f8d5b9e3c7a1f6d",
		ad:    "95a6b7c8d9eafb0c1d2e3f5061728394a5b6c7d8e9fa0b1c2d3e4f60718293a4b5c6d7e8f90a1b2c3d4e5f708192a3b4c5d6e7f8091a2b3c4d5e6f8091a2b3c4",
		msg: "32e14453e7a776781d4c4e2c3b23bca2" +
			"441ee4213bc3df25021b5106c22c98e8" +
			"a7b310142252c8dcff70a91d55cdc910" +
			"3c1eccd9b5309ef21793a664e0d4b63c" +
			"83530dcd1a6ad0feda6ff19153e9ee62" +
			"0325c1cb979d7b32e54f41da3af1c169" +
			"a24c47c1f6673e115f0cb73e8c507f15" +
			"eedf155261962f2d175c9ba3832f4933" +
			"fb330d28ad6aae787f12788706f45c92" +
			"e72aea146959d2d4fa01869f7d072a7b" +
			"f43b2e75265e1a000dde451b64658919" +
			"e93143d2781955fb4ca2a38076ac9eb4" +
			"9adc2b92b05f0ec7",
		expectedCt: "1d8d56867870574d1c4ac114620c6a2a" +
			"bb44680fe321dd116601e2c92540f85a" +
			"11c41dcac9814397b8f37b812cd52c93" +
			"2db6ecbaa247c3e14f228bd792334570" +
			"2fc43ad1eb1b8086e2c3c57bb602971c" +
			"29772a35dfb1c45c66f81633e67fdc8d" +
			"8005457ddbe4179312abab981049eb0a" +
			"0a555b9fa01378878d7349111e2446fd" +
			"e89ce64022d032cbf0cf2672e00d7999" +
			"ed8b631c1b9bee547cbe464673464a4b" +
			"80e8f72ad2b91a40fdcee5357980c090" +
			"b34ab5e732e2a7df7613131ee42e42ec" +
			"6ae9b05ac5683ebe",
		expectedTag: "e93686b266c481196d44536eb51b5f2d",
	},
	{
		name:        "Test Vector 8 - Single byte plaintext",
		key:         "7b6a5f4e3d2c1b0a9f8e7d6c5b4a3f2e1d0c9b8a7f6e5d4c3b2a1f0e9d8c7b6a",
		nonce:       "2e7c9f5d3b8a4c6f1e9b5d7a3f8c2e4a",
		ad:          "",
		msg:         "ff",
		expectedCt:  "21",
		expectedTag: "3cf9020bd1cc59cc5f2f6ce19f7cbf68",
	},
	{
		name:        "Test Vector 9 - Two blocks plaintext",
		key:         "4c8b7a9f3e5d2c6b1a8f9e7d6c5b4a3f2e1d0c9b8a7f6e5d4c3b2a1f0e9d8c7b",
		nonce:       "7e3c9a5f1d8b4e6c2a9f5d7b3e8c1a4f",
		ad:          "c3d4e5f60718293a4b5c6d7e8fa0b1c2d3e4f5061728394a5b6c7d8e9fb0c1d2e3f405162738495a6b7c8d9eafc0d1e2",
		msg:         "aa55f00fcc339669aa55f00fcc339669aa55f00fcc339669aa55f00fcc339669",
		expectedCt:  "c2e199ac8c23ce6e3778e7fd0b4f8f752badd4b67be0cdc3f6c98ae5f6fb0d25",
		expectedTag: "7aea3fbce699ceb1d0737e0483217745",
	},
	{
		name:  "Test Vector 10 - All zeros plaintext",
		key:   "9e8d7c6b5a4f3e2d1c0b9a8f7e6d5c4b3a2f1e0d9c8b7a6f5e4d3c2b1a0f9e8d",
		nonce: "5f9d3b7e2c8a4f6d1b9e5c7a3d8f2b6e",
		ad:    "daebfc0d1e2f405162738495a6b7c8d9",
		msg: "00000000000000000000000000000000" +
			"00000000000000000000000000000000" +
			"00000000000000000000000000000000" +
			"00000000000000000000000000000000" +
			"00000000000000000000000000000000" +
			"00000000000000000000000000000000" +
			"00000000000000000000000000000000" +
			"00000000000000000000000000000000",
		expectedCt: "fc7f1142f681399099c5008980e73420" +
			"65b4e62a9b9cb301bdf441d3282b6aa9" +
			"3bd7cd735ef77755b4109f86b7c09083" +
			"8e7b05f08ef4947946155a03ff483095" +
			"152ef3dec8bdddae3990d00d41d5ee6c" +
			"90dcf65dbed4b7ebbe9bb4ef096e1238" +
			"d388bf15faacdb7a68be19dddc8a5b74" +
			"216f4442bfa32d1dfccdc9c4020baec9",
		expectedTag: "ad0b841c3d145a6ee86dc7b67338f113",
	},
}

// hexDecode converts hex string to bytes, panics on error
func hexDecode(s string) []byte {
	if s == "" {
		return []byte{}
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		panic("invalid hex string: " + s)
	}
	return b
}

// hexEncode converts bytes to hex string
func hexEncode(b []byte) string {
	return hex.EncodeToString(b)
}

// TestHiAEVectors runs all specification test vectors
func TestHiAEVectors(t *testing.T) {
	for i, tv := range testVectors {
		t.Run(tv.name, func(t *testing.T) {
			// Decode test vector data
			key := hexDecode(tv.key)
			nonce := hexDecode(tv.nonce)
			ad := hexDecode(tv.ad)
			msg := hexDecode(tv.msg)
			expectedCt := hexDecode(tv.expectedCt)
			expectedTag := hexDecode(tv.expectedTag)

			// Test encryption
			ct, tag, err := Encrypt(msg, ad, key, nonce)
			if err != nil {
				t.Fatalf("Vector %d: Encrypt failed: %v", i+1, err)
			}

			// Verify ciphertext
			if hexEncode(ct) != hexEncode(expectedCt) {
				t.Errorf("Vector %d: Ciphertext mismatch\nExpected: %s\nGot:      %s",
					i+1, hexEncode(expectedCt), hexEncode(ct))
			}

			// Verify tag
			if hexEncode(tag) != hexEncode(expectedTag) {
				t.Errorf("Vector %d: Tag mismatch\nExpected: %s\nGot:      %s",
					i+1, hexEncode(expectedTag), hexEncode(tag))
			}

			// Test decryption
			decryptedMsg, err := Decrypt(ct, tag, ad, key, nonce)
			if err != nil {
				t.Fatalf("Vector %d: Decrypt failed: %v", i+1, err)
			}

			// Verify decrypted message
			if hexEncode(decryptedMsg) != hexEncode(msg) {
				t.Errorf("Vector %d: Decrypted message mismatch\nExpected: %s\nGot:      %s",
					i+1, hexEncode(msg), hexEncode(decryptedMsg))
			}

			// Test authentication failure with wrong tag
			wrongTag := make([]byte, len(tag))
			copy(wrongTag, tag)
			if len(wrongTag) > 0 {
				wrongTag[0] ^= 0x01 // Flip one bit
			}

			_, err = Decrypt(ct, wrongTag, ad, key, nonce)
			if err == nil {
				t.Errorf("Vector %d: Decrypt should have failed with wrong tag", i+1)
			}
		})
	}
}

// TestAESL verifies the AESL function with the example from the specification
func TestAESL(t *testing.T) {
	input := hexDecode("00112233445566778899aabbccddeeff")
	expected := hexDecode("6379e6d9f467fb76ad063cf4d2eb8aa3")

	result := AESL(input)
	if hexEncode(result) != hexEncode(expected) {
		t.Errorf("AESL test failed\nExpected: %s\nGot:      %s",
			hexEncode(expected), hexEncode(result))
	}
}

// TestUtilityFunctions tests various utility functions
func TestUtilityFunctions(t *testing.T) {
	a := []byte{0x01, 0x02, 0x03}
	b := []byte{0x04, 0x05, 0x06}
	expected := []byte{0x05, 0x07, 0x05}
	result := xorBytes(a, b)
	if hexEncode(result) != hexEncode(expected) {
		t.Errorf("XOR failed\nExpected: %s\nGot:      %s",
			hexEncode(expected), hexEncode(result))
	}

	result64 := le64(0x0123456789abcdef)
	expected64 := []byte{0xef, 0xcd, 0xab, 0x89, 0x67, 0x45, 0x23, 0x01}
	if hexEncode(result64) != hexEncode(expected64) {
		t.Errorf("le64 failed\nExpected: %s\nGot:      %s",
			hexEncode(expected64), hexEncode(result64))
	}

	data := []byte{0x01, 0x02, 0x03}
	padded := zeroPad(data, 8)
	expectedPad := []byte{0x01, 0x02, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00}
	if hexEncode(padded) != hexEncode(expectedPad) {
		t.Errorf("zeroPad failed\nExpected: %s\nGot:      %s",
			hexEncode(expectedPad), hexEncode(padded))
	}
}

// TestKeyNonceLengths tests that the implementation rejects invalid key/nonce lengths
func TestKeyNonceLengths(t *testing.T) {
	validKey := make([]byte, 32)
	validNonce := make([]byte, 16)
	validAd := []byte{}
	validMsg := []byte{}

	invalidKey := make([]byte, 31)
	_, _, err := Encrypt(validMsg, validAd, invalidKey, validNonce)
	if err == nil {
		t.Error("Expected error for invalid key length")
	}

	invalidNonce := make([]byte, 15)
	_, _, err = Encrypt(validMsg, validAd, validKey, invalidNonce)
	if err == nil {
		t.Error("Expected error for invalid nonce length")
	}

	ct := []byte{}
	invalidTag := make([]byte, 15)
	_, err = Decrypt(ct, invalidTag, validAd, validKey, validNonce)
	if err == nil {
		t.Error("Expected error for invalid tag length")
	}
}

// benchmarkEncrypt benchmarks encryption for a given message size
func benchmarkEncrypt(b *testing.B, size int) {
	key := make([]byte, 32)
	nonce := make([]byte, 16)
	msg := make([]byte, size)
	ad := []byte{}
	ct := make([]byte, size)
	tag := make([]byte, 16)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = EncryptTo(msg, ad, key, nonce, ct, tag)
	}

	bytesProcessed := int64(b.N) * int64(size)
	mbitsProcessed := float64(bytesProcessed) * 8 / 1e6
	mbitsPerSec := mbitsProcessed / b.Elapsed().Seconds()
	b.ReportMetric(mbitsPerSec, "Mb/s")
}

// benchmarkDecrypt benchmarks decryption for a given message size
func benchmarkDecrypt(b *testing.B, size int) {
	key := make([]byte, 32)
	nonce := make([]byte, 16)
	msg := make([]byte, size)
	ad := []byte{}
	ct := make([]byte, size)
	tag := make([]byte, 16)
	msgOut := make([]byte, size)

	_ = EncryptTo(msg, ad, key, nonce, ct, tag)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = DecryptTo(ct, tag, ad, key, nonce, msgOut)
	}

	bytesProcessed := int64(b.N) * int64(size)
	mbitsProcessed := float64(bytesProcessed) * 8 / 1e6
	mbitsPerSec := mbitsProcessed / b.Elapsed().Seconds()
	b.ReportMetric(mbitsPerSec, "Mb/s")
}

// Encryption benchmarks for various sizes
func BenchmarkEncrypt16B(b *testing.B)  { benchmarkEncrypt(b, 16) }
func BenchmarkEncrypt32B(b *testing.B)  { benchmarkEncrypt(b, 32) }
func BenchmarkEncrypt64B(b *testing.B)  { benchmarkEncrypt(b, 64) }
func BenchmarkEncrypt128B(b *testing.B) { benchmarkEncrypt(b, 128) }
func BenchmarkEncrypt256B(b *testing.B) { benchmarkEncrypt(b, 256) }
func BenchmarkEncrypt512B(b *testing.B) { benchmarkEncrypt(b, 512) }
func BenchmarkEncrypt1KB(b *testing.B)  { benchmarkEncrypt(b, 1024) }
func BenchmarkEncrypt2KB(b *testing.B)  { benchmarkEncrypt(b, 2048) }
func BenchmarkEncrypt4KB(b *testing.B)  { benchmarkEncrypt(b, 4096) }
func BenchmarkEncrypt8KB(b *testing.B)  { benchmarkEncrypt(b, 8192) }
func BenchmarkEncrypt16KB(b *testing.B) { benchmarkEncrypt(b, 16384) }
func BenchmarkEncrypt32KB(b *testing.B) { benchmarkEncrypt(b, 32768) }
func BenchmarkEncrypt64KB(b *testing.B) { benchmarkEncrypt(b, 65536) }

// Decryption benchmarks for various sizes
func BenchmarkDecrypt16B(b *testing.B)  { benchmarkDecrypt(b, 16) }
func BenchmarkDecrypt32B(b *testing.B)  { benchmarkDecrypt(b, 32) }
func BenchmarkDecrypt64B(b *testing.B)  { benchmarkDecrypt(b, 64) }
func BenchmarkDecrypt128B(b *testing.B) { benchmarkDecrypt(b, 128) }
func BenchmarkDecrypt256B(b *testing.B) { benchmarkDecrypt(b, 256) }
func BenchmarkDecrypt512B(b *testing.B) { benchmarkDecrypt(b, 512) }
func BenchmarkDecrypt1KB(b *testing.B)  { benchmarkDecrypt(b, 1024) }
func BenchmarkDecrypt2KB(b *testing.B)  { benchmarkDecrypt(b, 2048) }
func BenchmarkDecrypt4KB(b *testing.B)  { benchmarkDecrypt(b, 4096) }
func BenchmarkDecrypt8KB(b *testing.B)  { benchmarkDecrypt(b, 8192) }
func BenchmarkDecrypt16KB(b *testing.B) { benchmarkDecrypt(b, 16384) }
func BenchmarkDecrypt32KB(b *testing.B) { benchmarkDecrypt(b, 32768) }
func BenchmarkDecrypt64KB(b *testing.B) { benchmarkDecrypt(b, 65536) }
