// SPDX-License-Identifier: AGPL-3.0-only

package wtp

import (
	"crypto/ed25519"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
)

func load(t *testing.T, name string) any {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	v, err := ParseWith(b, Limits{MaxBytes: 64 << 20, MaxDepth: 64, AllowUnicodeKeys: true})
	if err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	return v
}

func TestJCSPairs(t *testing.T) {
	for i, c := range load(t, "jcs_pairs.json").([]any) {
		m := c.(map[string]any)
		got, err := JCS(m["input"])
		if err != nil {
			t.Fatal(err)
		}
		if string(got) != m["canonical"].(string) {
			t.Errorf("case %d: got %s want %s", i, got, m["canonical"])
		}
	}
}

func TestDCBORPairs(t *testing.T) {
	for i, c := range load(t, "dcbor_pairs.json").([]any) {
		m := c.(map[string]any)
		got, err := DCBOR(m["input"])
		if err != nil {
			t.Fatal(err)
		}
		if hex.EncodeToString(got) != m["dcbor_hex"].(string) {
			t.Errorf("case %d: got %x want %s", i, got, m["dcbor_hex"])
		}
	}
}

func TestSHA256(t *testing.T) {
	for _, c := range load(t, "sha256.json").([]any) {
		m := c.(map[string]any)
		h, ok := m["bytes_hex"].(string)
		if !ok {
			continue // a case without input bytes (documented erratum)
		}
		b, _ := hex.DecodeString(h)
		if SHA256Digest(b) != "sha256:"+m["sha256"].(string) {
			t.Errorf("case %v mismatch", m["case"])
		}
	}
}

func TestStrictNegative(t *testing.T) {
	for i, c := range load(t, "crosslang/strict_json_negative.json").([]any) {
		b, _ := hex.DecodeString(c.(map[string]any)["hex"].(string))
		if _, err := Parse(b); err == nil {
			t.Errorf("case %d (%q) accepted", i, b)
		}
	}
}

func TestStrictAccepts(t *testing.T) {
	v, err := Parse([]byte(` {"a":[1,-2,"\ud834\udf06",true,null],"b":{}} `))
	if err != nil || v.(map[string]any)["a"].([]any)[1] != int64(-2) {
		t.Fatalf("%v %v", v, err)
	}
}

func TestSignatureVectors(t *testing.T) {
	d := load(t, "crosslang/signatures.json").(map[string]any)
	seed, _ := hex.DecodeString(d["seed_hex"].(string))
	key := ed25519.NewKeyFromSeed(seed)
	pub := key.Public().(ed25519.PublicKey)
	a := Auth{SignerID: d["signer_id"].(string), KeyID: d["key_id"].(string), IssuedAt: d["issued_at"].(string), Nonce: d["nonce"].(string)}
	cases := d["cases"].([]any)
	if len(cases) != 24 {
		t.Fatalf("expected 24 kinds, got %d", len(cases))
	}
	for _, c := range cases {
		m := c.(map[string]any)
		name := m["name"].(string)
		ex := m["example"].(map[string]any)
		j, err := JCS(ex)
		if err != nil || string(j) != m["jcs_unsigned_example"].(string) {
			t.Errorf("%s: JCS mismatch", name)
		}
		if SHA256Digest(j) != m["jcs_sha256"].(string) {
			t.Errorf("%s: digest mismatch", name)
		}
		if cb, _ := DCBOR(ex); hex.EncodeToString(cb) != m["dcbor_hex_example"].(string) {
			t.Errorf("%s: dCBOR mismatch", name)
		}
		signed, err := Sign(ex, key, a, EncodingJCS)
		if err != nil {
			t.Fatal(err)
		}
		want, _ := JCS(m["signed_jcs"])
		got, _ := JCS(signed)
		if string(got) != string(want) {
			t.Errorf("%s: signed JCS envelope differs from reference", name)
		}
		in, _ := SigningInput(signed, EncodingJCS)
		if string(in) != string(JCSPrefix)+m["jcs_signing_input"].(string) {
			t.Errorf("%s: signing input mismatch", name)
		}
		if err := Verify(m["signed_jcs"].(map[string]any), pub); err != nil {
			t.Errorf("%s: reference signature rejected: %v", name, err)
		}
		cs, _ := Sign(ex, key, a, EncodingDCBOR)
		if cb, _ := DCBOR(cs); hex.EncodeToString(cb) != m["signed_dcbor_hex"].(string) {
			t.Errorf("%s: signed dCBOR mismatch", name)
		}
		if err := Verify(cs, pub); err != nil {
			t.Errorf("%s: dcbor verify: %v", name, err)
		}
		// Tamper: any payload change must break the signature.
		tampered := map[string]any{}
		for k, v := range signed {
			tampered[k] = v
		}
		tampered["occurred_at"] = "2026-10-18T10:00:01Z"
		if Verify(tampered, pub) == nil {
			t.Errorf("%s: tampered envelope verified", name)
		}
	}
}

func TestSmallOrderRejected(t *testing.T) {
	k, _ := hex.DecodeString(SmallOrderPublicKeys[1])
	if ValidatePublicKey(k) == nil {
		t.Fatal("small-order key accepted")
	}
}

func TestTaskTransitions(t *testing.T) {
	for _, c := range load(t, "crosslang/task_transitions.json").([]any) {
		m := c.(map[string]any)
		err := CheckTransition(TaskState(m["from"].(string)), TaskState(m["to"].(string)))
		if (err == nil) != m["allowed"].(bool) {
			t.Errorf("%v → %v: got %v", m["from"], m["to"], err)
		}
	}
}

func TestRelativePaths(t *testing.T) {
	for _, c := range load(t, "crosslang/relative_paths.json").([]any) {
		m := c.(map[string]any)
		p := m["path"].(string)
		if (ValidateRelativePath(p) == nil) != m["valid"].(bool) {
			t.Errorf("%q: expected valid=%v", p, m["valid"])
		}
	}
}
