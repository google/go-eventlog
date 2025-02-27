package cel

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"fmt"
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
	tests := []MRType{PCRType, CCMRType}

	for _, tc := range tests {
		t.Run(fmt.Sprintf("MRType %v", tc), func(t *testing.T) {
			cel := eventLog{Type: tc}

			fakeEvent1 := FakeTlv{FakeEvent1, []byte("docker.io/bazel/experimental/test:latest")}
			appendFakeMREventOrFatal(t, &cel, rot, 16, measuredHashes, fakeEvent1)

			fakeEvent2 := FakeTlv{FakeEvent2, []byte("sha256:781d8dfdd92118436bd914442c8339e653b83f6bf3c1a7a98efcfb7c4fed7483")}
			appendFakeMREventOrFatal(t, &cel, rot, 23, measuredHashes, fakeEvent2)

			var buf bytes.Buffer
			if err := cel.EncodeCEL(&buf); err != nil {
				t.Fatal(err)
			}
			decodedcel, err := DecodeToCEL(&buf)
			if err != nil {
				t.Fatal(err)
			}
			if decodedcel.MRType() != tc {
				t.Errorf("decoded CEL MR type: got %v, want %v", decodedcel.MRType(), tc)
			}
			if len(decodedcel.Records()) != 2 {
				t.Errorf("should have two records")
			}
			if decodedcel.Records()[0].RecNum != 0 {
				t.Errorf("recnum mismatch")
			}
			if decodedcel.Records()[1].RecNum != 1 {
				t.Errorf("recnum mismatch")
			}
			if decodedcel.Records()[0].IndexType != tc {
				t.Errorf("index type mismatch")
			}
			if decodedcel.Records()[0].Index != uint8(16) {
				t.Errorf("pcr value mismatch")
			}
			if decodedcel.Records()[1].IndexType != tc {
				t.Errorf("index type mismatch")
			}
			if decodedcel.Records()[1].Index != uint8(23) {
				t.Errorf("pcr value mismatch")
			}

			if !reflect.DeepEqual(decodedcel.Records(), cel.Records()) {
				t.Errorf("decoded CEL doesn't equal to the original one")
			}
		})
	}
}

func TestCELAppendDifferentMRTypes(t *testing.T) {
	rot, err := register.CreateFakeRot(measuredHashes, 24)
	if err != nil {
		t.Fatal(err)
	}

	tests := []MRType{PCRType, CCMRType}

	for _, tc := range tests {
		t.Run(fmt.Sprintf("MRType %v", tc), func(t *testing.T) {
			el := eventLog{Type: tc}
			event := FakeTlv{FakeEvent1, []byte("hellothere")}

			appendFakeMREventOrFatal(t, &el, rot, 8, measuredHashes, event)
			appendFakeMREventOrFatal(t, &el, rot, 8, measuredHashes, event)
			appendFakeMREventOrFatal(t, &el, rot, 8, measuredHashes, event)
			appendFakeMREventOrFatal(t, &el, rot, 8, measuredHashes, event)
			appendFakeMREventOrFatal(t, &el, rot, 8, measuredHashes, event)

			for _, rec := range el.Records() {
				if rec.IndexType != tc {
					t.Errorf("AppendEvent(): got Index Type %v, want type %v", rec.IndexType, tc)
				}
			}
		})
	}
}

func TestCELMeasureAndReplay(t *testing.T) {
	rot, err := register.CreateFakeRot(measuredHashes, 24)
	if err != nil {
		t.Fatal(err)
	}

	cel := NewPCR()
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
	cel := NewPCR()

	event := FakeTlv{FakeEvent1, []byte("docker.io/bazel/experimental/test:latest")}
	someEvent2 := make([]byte, 10)
	rand.Read(someEvent2)
	FakeEvent2 := FakeTlv{FakeEvent2, someEvent2}

	appendFakeMREventOrFatal(t, cel, rot, 2, measuredHashes, event)
	appendFakeMREventOrFatal(t, cel, rot, 2, measuredHashes, FakeEvent2)
	appendFakeMREventOrFatal(t, cel, rot, 3, measuredHashes, FakeEvent2)
	appendFakeMREventOrFatal(t, cel, rot, 3, measuredHashes, event)
	appendFakeMREventOrFatal(t, cel, rot, 3, measuredHashes, event)

	modifiedRecord := cel.Records()[3]
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
	cel := NewPCR()
	replay(t, cel, rot, []crypto.Hash{crypto.SHA1, crypto.SHA256},
		[]int{12, 13}, true /*shouldSucceed*/)
}

func TestCELReplayFailMissingMRsInBank(t *testing.T) {
	rot, err := register.CreateFakeRot(measuredHashes, 24)
	if err != nil {
		t.Fatal(err)
	}
	cel := &eventLog{Type: PCRType}

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

func TestDecodeCELFailBadMRTypes(t *testing.T) {
	rot, err := register.CreateFakeRot(measuredHashes, 24)
	if err != nil {
		t.Fatal(err)
	}
	cel := &eventLog{}
	someEvent := make([]byte, 10)
	if err := cel.AppendEvent(FakeTlv{FakeEvent1, someEvent}, measuredHashes, 7, fakeRotExtender(rot)); err == nil {
		t.Errorf("AppendEvent(UnsetMR): got %v, expect err", err)
	}

}

func TestCELAppendFailBadMRType(t *testing.T) {
	rot, err := register.CreateFakeRot(measuredHashes, 24)
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		mrT       MRType
		expectErr bool
	}{
		{mrT: PCRType, expectErr: false},
		{mrT: CCMRType, expectErr: false},
		{mrT: 0, expectErr: true},
		{mrT: 2, expectErr: true},
		{mrT: 4, expectErr: true},
		{mrT: 100, expectErr: true},
		{mrT: 100, expectErr: true},
		{mrT: 255, expectErr: true},
	}

	for _, tc := range tests {
		t.Run(fmt.Sprintf("MRType %v", tc.mrT), func(t *testing.T) {
			cel := &eventLog{Type: tc.mrT}
			someEvent := make([]byte, 10)
			if err := cel.AppendEvent(FakeTlv{FakeEvent1, someEvent}, measuredHashes, 7, fakeRotExtender(rot)); (err != nil) != tc.expectErr {
				t.Errorf("AppendEvent(MRType %v): got %v, expectErr %v", tc.mrT, err, tc.expectErr)
			}
		})
	}
}

func replay(t *testing.T, cel CEL, rot register.FakeROT, measuredHashes []crypto.Hash, mrs []int, shouldSucceed bool) {
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

func appendFakeMREventOrFatal(t *testing.T, cel CEL, fakeROT register.FakeROT, mrIndex int, banks []crypto.Hash, event Content) {
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
