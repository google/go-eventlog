package cel

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"reflect"
	"testing"

	"github.com/google/go-eventlog/register"
)

var measuredHashes = []crypto.Hash{crypto.SHA1, crypto.SHA256}

func TestCELEncodingDecoding(t *testing.T) {
	rot, err := register.CreateFakeRot(measuredHashes, 24)
	if err != nil {
		t.Fatal(err)
	}

	cel := &CEL{}

	fakeEvent1 := FakeTlv{FakeEvent1, []byte("docker.io/bazel/experimental/test:latest")}
	appendFakeMREventOrFatal(t, cel, rot, 16, measuredHashes, fakeEvent1)

	fakeEvent2 := FakeTlv{FakeEvent2, []byte("sha256:781d8dfdd92118436bd914442c8339e653b83f6bf3c1a7a98efcfb7c4fed7483")}
	appendFakeMREventOrFatal(t, cel, rot, 23, measuredHashes, fakeEvent2)

	var buf bytes.Buffer
	if err := cel.EncodeCEL(&buf); err != nil {
		t.Fatal(err)
	}
	decodedcel, err := DecodeToCEL(&buf)
	if err != nil {
		t.Fatal(err)
	}
	if len(decodedcel.Records) != 2 {
		t.Errorf("should have two records")
	}
	if decodedcel.Records[0].RecNum != 0 {
		t.Errorf("recnum mismatch")
	}
	if decodedcel.Records[1].RecNum != 1 {
		t.Errorf("recnum mismatch")
	}
	if decodedcel.Records[0].IndexType != PCRTypeValue {
		t.Errorf("index type mismatch")
	}
	if decodedcel.Records[0].Index != uint8(16) {
		t.Errorf("pcr value mismatch")
	}
	if decodedcel.Records[1].IndexType != PCRTypeValue {
		t.Errorf("index type mismatch")
	}
	if decodedcel.Records[1].Index != uint8(23) {
		t.Errorf("pcr value mismatch")
	}

	if !reflect.DeepEqual(decodedcel.Records, cel.Records) {
		t.Errorf("decoded CEL doesn't equal to the original one")
	}
}

func TestCELMeasureAndReplay(t *testing.T) {
	rot, err := register.CreateFakeRot(measuredHashes, 24)
	if err != nil {
		t.Fatal(err)
	}

	cel := &CEL{}
	event := FakeTlv{FakeEvent1, []byte("docker.io/bazel/experimental/test:latest")}

	someEvent2 := make([]byte, 10)
	rand.Read(someEvent2)
	FakeEvent2 := FakeTlv{FakeEvent2, someEvent2}

	appendFakeMREventOrFatal(t, cel, rot, 12, measuredHashes, event)
	appendFakeMREventOrFatal(t, cel, rot, 12, measuredHashes, FakeEvent2)

	appendFakeMREventOrFatal(t, cel, rot, 18, measuredHashes, FakeEvent2)
	appendFakeMREventOrFatal(t, cel, rot, 18, measuredHashes, event)
	appendFakeMREventOrFatal(t, cel, rot, 18, measuredHashes, event)

	replay(t, cel, rot, measuredHashes,
		[]int{12, 18}, true /*shouldSucceed*/)
	// Supersets should pass.
	replay(t, cel, rot, measuredHashes,
		[]int{0, 12, 13, 14, 18, 19, 22, 23}, true /*shouldSucceed*/)
}

func TestCELReplayFailTamperedDigest(t *testing.T) {
	rot, err := register.CreateFakeRot(measuredHashes, 24)
	if err != nil {
		t.Fatal(err)
	}
	cel := &CEL{}

	event := FakeTlv{FakeEvent1, []byte("docker.io/bazel/experimental/test:latest")}
	someEvent2 := make([]byte, 10)
	rand.Read(someEvent2)
	FakeEvent2 := FakeTlv{FakeEvent2, someEvent2}

	appendFakeMREventOrFatal(t, cel, rot, 2, measuredHashes, event)
	appendFakeMREventOrFatal(t, cel, rot, 2, measuredHashes, FakeEvent2)
	appendFakeMREventOrFatal(t, cel, rot, 3, measuredHashes, FakeEvent2)
	appendFakeMREventOrFatal(t, cel, rot, 3, measuredHashes, event)
	appendFakeMREventOrFatal(t, cel, rot, 3, measuredHashes, event)

	modifiedRecord := cel.Records[3]
	for hash := range modifiedRecord.Digests {
		newDigest := make([]byte, hash.Size())
		rand.Read(newDigest)
		modifiedRecord.Digests[hash] = newDigest
	}
	replay(t, cel, rot, measuredHashes,
		[]int{2, 3}, false /*shouldSucceed*/)
}

func TestCELReplayEmpty(t *testing.T) {
	rot, err := register.CreateFakeRot(measuredHashes, 24)
	if err != nil {
		t.Fatal(err)
	}
	cel := &CEL{}
	replay(t, cel, rot, []crypto.Hash{crypto.SHA1, crypto.SHA256},
		[]int{12, 13}, true /*shouldSucceed*/)
}

func TestCELReplayFailMissingMRsInBank(t *testing.T) {
	rot, err := register.CreateFakeRot(measuredHashes, 24)
	if err != nil {
		t.Fatal(err)
	}
	cel := &CEL{}

	someEvent := make([]byte, 10)
	someEvent2 := make([]byte, 10)
	rand.Read(someEvent2)

	appendFakeMREventOrFatal(t, cel, rot, 7, measuredHashes, FakeTlv{FakeEvent1, someEvent})
	appendFakeMREventOrFatal(t, cel, rot, 8, measuredHashes, FakeTlv{FakeEvent2, someEvent2})

	replay(t, cel, rot, measuredHashes,
		[]int{7}, false /*shouldSucceed*/)
	replay(t, cel, rot, measuredHashes,
		[]int{8}, false /*shouldSucceed*/)
}

func replay(t *testing.T, cel *CEL, rot register.FakeROT, measuredHashes []crypto.Hash, mrs []int, shouldSucceed bool) {
	for _, hash := range measuredHashes {
		bank, err := rot.ReadMRs(hash, mrs)
		if err != nil {
			t.Fatal(err)
		}
		if err := cel.Replay(bank); shouldSucceed && err != nil {
			t.Errorf("failed to replay CEL on %v bank: %v",
				hash, err)
		}
	}
}

func appendFakeMREventOrFatal(t *testing.T, cel *CEL, fakeROT register.FakeROT, mrIndex int, banks []crypto.Hash, event Content) {
	if err := cel.AppendEvent(event, banks, mrIndex, fakeRotExtender(fakeROT)); err != nil {
		t.Fatalf("failed to append PCR event: %v", err)
	}
}

func fakeRotExtender(rot register.FakeROT) MRExtender {
	return func(bank crypto.Hash, mrIdx int, digest []byte) error {
		return rot.ExtendMR(register.FakeMR{
			Index:     mrIdx,
			Digest:    digest,
			DigestAlg: bank,
		})
	}
}
