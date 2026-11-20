// Copyright (c) 2015-2024 MinIO, Inc.
//
// This file is part of MinIO Object Storage stack
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

package auth

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"reflect"
	"strings"
	"testing"
	"testing/iotest"
	"time"

	jwtgo "github.com/golang-jwt/jwt/v4"
)

func TestContainsReservedChars(t *testing.T) {
	testCases := []struct {
		input    string
		expected bool
	}{
		{"", false},
		{"minioadmin", false},
		{"user-name_1.2", false},
		{"a=b", true},
		{"a,b", true},
		{"=", true},
		{",", true},
		{"key=", true},
		{",key", true},
	}
	for _, tc := range testCases {
		if got := ContainsReservedChars(tc.input); got != tc.expected {
			t.Errorf("ContainsReservedChars(%q) = %v, want %v", tc.input, got, tc.expected)
		}
	}
}

func TestExpToInt64Values(t *testing.T) {
	now := time.Now().UTC()
	testCases := []struct {
		name     string
		exp      any
		expected int64
		err      error
	}{
		{"nil", nil, 0, nil},
		{"string", "1574812326", 1574812326, nil},
		{"non-numeric string", "abc", 0, nil}, // err is a strconv error, checked below
		{"float64", float64(1574812326), 1574812326, nil},
		{"int64", int64(1574812326), 1574812326, nil},
		{"int", 1574812326, 1574812326, nil},
		{"uint64", uint64(1574812326), 1574812326, nil},
		{"uint", uint(1574812326), 1574812326, nil},
		{"json.Number", json.Number("1574812326"), 1574812326, nil},
		{"json.Number invalid", json.Number("1.5x"), 0, nil}, // err is a strconv error, checked below
		{"negative int", -1, 0, ErrInvalidDuration},
		{"negative int64", int64(-5), 0, ErrInvalidDuration},
		{"negative float64", float64(-1), 0, ErrInvalidDuration},
		{"unsupported type", true, 0, ErrInvalidDuration},
		{"unsupported struct", struct{}{}, 0, ErrInvalidDuration},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ExpToInt64(tc.exp)
			switch tc.name {
			case "non-numeric string", "json.Number invalid":
				if err == nil {
					t.Fatal("expected a parse error, got nil")
				}
				return
			}
			if !errors.Is(err, tc.err) {
				t.Fatalf("error: got %v, want %v", err, tc.err)
			}
			if got != tc.expected {
				t.Fatalf("value: got %d, want %d", got, tc.expected)
			}
		})
	}

	t.Run("duration", func(t *testing.T) {
		got, err := ExpToInt64(5 * time.Minute)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		lo := now.Add(5 * time.Minute).Unix()
		hi := time.Now().UTC().Add(5 * time.Minute).Unix()
		if got < lo || got > hi {
			t.Fatalf("duration expiry %d not within [%d, %d]", got, lo, hi)
		}
	})
}

func TestCredentialsString(t *testing.T) {
	exp := time.Date(2030, time.January, 2, 3, 4, 5, 0, time.UTC)
	testCases := []struct {
		name     string
		cred     Credentials
		expected string
	}{
		{"anonymous", AnonymousCredentials, ":"},
		{"keys only", Credentials{AccessKey: "ak", SecretKey: "sk"}, "ak:sk"},
		{"sentinel expiry is hidden", Credentials{AccessKey: "ak", SecretKey: "sk", Expiration: timeSentinel}, "ak:sk"},
		{"with token", Credentials{AccessKey: "ak", SecretKey: "sk", SessionToken: "tok"}, "ak:sk\ntok"},
		{"with expiry", Credentials{AccessKey: "ak", SecretKey: "sk", Expiration: exp}, "ak:sk\n" + exp.String()},
		{"with token and expiry", Credentials{AccessKey: "ak", SecretKey: "sk", SessionToken: "tok", Expiration: exp}, "ak:sk\ntok\n" + exp.String()},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.cred.String(); got != tc.expected {
				t.Fatalf("got %q, want %q", got, tc.expected)
			}
		})
	}
}

func TestCredentialsIsExpired(t *testing.T) {
	testCases := []struct {
		name     string
		exp      time.Time
		expected bool
	}{
		{"zero", time.Time{}, false},
		{"sentinel", timeSentinel, false},
		{"future", time.Now().UTC().Add(time.Hour), false},
		{"past", time.Now().UTC().Add(-time.Hour), true},
		{"epoch+1s is in the past", time.Unix(1, 0).UTC(), true},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			cred := Credentials{Expiration: tc.exp}
			if got := cred.IsExpired(); got != tc.expected {
				t.Fatalf("got %v, want %v", got, tc.expected)
			}
		})
	}
}

func TestCredentialsIsTemp(t *testing.T) {
	future := time.Now().UTC().Add(time.Hour)
	testCases := []struct {
		name     string
		cred     Credentials
		expected bool
	}{
		{"no token no expiry", Credentials{}, false},
		{"token but zero expiry", Credentials{SessionToken: "tok"}, false},
		{"token but sentinel expiry", Credentials{SessionToken: "tok", Expiration: timeSentinel}, false},
		{"expiry but no token", Credentials{Expiration: future}, false},
		{"token and expiry", Credentials{SessionToken: "tok", Expiration: future}, true},
		{"token and past expiry is still temp", Credentials{SessionToken: "tok", Expiration: time.Unix(10, 0).UTC()}, true},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.cred.IsTemp(); got != tc.expected {
				t.Fatalf("got %v, want %v", got, tc.expected)
			}
		})
	}
}

func TestCredentialsServiceAccount(t *testing.T) {
	testCases := []struct {
		name            string
		cred            Credentials
		isSA            bool
		isImpliedPolicy bool
	}{
		{"plain", Credentials{}, false, false},
		{"parent user without claim", Credentials{ParentUser: "parent"}, false, false},
		{"claim without parent user", Credentials{Claims: map[string]any{iamPolicyClaimNameSA: "inherited-policy"}}, false, false},
		{"embedded policy", Credentials{ParentUser: "parent", Claims: map[string]any{iamPolicyClaimNameSA: "embedded-policy"}}, true, false},
		{"inherited policy", Credentials{ParentUser: "parent", Claims: map[string]any{iamPolicyClaimNameSA: "inherited-policy"}}, true, true},
		{"nil claim value", Credentials{ParentUser: "parent", Claims: map[string]any{iamPolicyClaimNameSA: nil}}, true, false},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.cred.IsServiceAccount(); got != tc.isSA {
				t.Fatalf("IsServiceAccount: got %v, want %v", got, tc.isSA)
			}
			if got := tc.cred.IsImpliedPolicy(); got != tc.isImpliedPolicy {
				t.Fatalf("IsImpliedPolicy: got %v, want %v", got, tc.isImpliedPolicy)
			}
		})
	}
}

func TestCredentialsIsValid(t *testing.T) {
	ak := alphaNumericTable[:accessKeyMinLen]
	sk := alphaNumericTable[:secretKeyMinLen]
	testCases := []struct {
		name     string
		cred     Credentials
		expected bool
	}{
		{"anonymous", AnonymousCredentials, false},
		{"default", DefaultCredentials, true},
		{"minimum keys, no status", Credentials{AccessKey: ak, SecretKey: sk}, true},
		{"status on", Credentials{AccessKey: ak, SecretKey: sk, Status: AccountOn}, true},
		{"status off", Credentials{AccessKey: ak, SecretKey: sk, Status: AccountOff}, false},
		{"unknown status is treated as enabled", Credentials{AccessKey: ak, SecretKey: sk, Status: "unknown"}, true},
		{"short access key", Credentials{AccessKey: ak[:accessKeyMinLen-1], SecretKey: sk}, false},
		{"short secret key", Credentials{AccessKey: ak, SecretKey: sk[:secretKeyMinLen-1]}, false},
		{"expired", Credentials{AccessKey: ak, SecretKey: sk, Expiration: time.Now().UTC().Add(-time.Second)}, false},
		{"not yet expired", Credentials{AccessKey: ak, SecretKey: sk, Expiration: time.Now().UTC().Add(time.Hour)}, true},
		{"sentinel expiry", Credentials{AccessKey: ak, SecretKey: sk, Expiration: timeSentinel}, true},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.cred.IsValid(); got != tc.expected {
				t.Fatalf("got %v, want %v", got, tc.expected)
			}
		})
	}
}

func TestCredentialsEqualSessionTokenAndStatus(t *testing.T) {
	cred, err := GetNewCredentials()
	if err != nil {
		t.Fatalf("GetNewCredentials: %v", err)
	}
	withToken := cred
	withToken.SessionToken = "token-a"
	otherToken := cred
	otherToken.SessionToken = "token-b"
	disabled := cred
	disabled.Status = AccountOff
	expired := cred
	expired.Expiration = time.Now().UTC().Add(-time.Minute)

	testCases := []struct {
		name     string
		cred     Credentials
		ccred    Credentials
		expected bool
	}{
		{"same token", withToken, withToken, true},
		{"different token", withToken, otherToken, false},
		{"token vs no token", cred, withToken, false},
		// Equal only validates the argument, not the receiver.
		{"disabled argument", cred, disabled, false},
		{"disabled receiver", disabled, cred, true},
		{"expired argument", cred, expired, false},
		{"expired receiver", expired, cred, true},
		{"anonymous vs anonymous", AnonymousCredentials, AnonymousCredentials, false},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.cred.Equal(tc.ccred); got != tc.expected {
				t.Fatalf("got %v, want %v", got, tc.expected)
			}
		})
	}
}

func TestGenerateAccessKey(t *testing.T) {
	t.Run("default length", func(t *testing.T) {
		for _, length := range []int{0, -1} {
			key, err := GenerateAccessKey(length, nil)
			if err != nil {
				t.Fatalf("length %d: unexpected error: %v", length, err)
			}
			if len(key) != accessKeyMaxLen {
				t.Fatalf("length %d: got key length %d, want %d", length, len(key), accessKeyMaxLen)
			}
		}
	})

	t.Run("explicit lengths", func(t *testing.T) {
		for _, length := range []int{accessKeyMinLen, 10, accessKeyMaxLen, 64} {
			key, err := GenerateAccessKey(length, nil)
			if err != nil {
				t.Fatalf("length %d: unexpected error: %v", length, err)
			}
			if len(key) != length {
				t.Fatalf("length %d: got key length %d", length, len(key))
			}
			if !IsAccessKeyValid(key) {
				t.Fatalf("length %d: generated key %q is not valid", length, key)
			}
		}
	})

	t.Run("too short", func(t *testing.T) {
		for _, length := range []int{1, accessKeyMinLen - 1} {
			if _, err := GenerateAccessKey(length, nil); err == nil {
				t.Fatalf("length %d: expected error, got nil", length)
			}
		}
	})

	t.Run("charset", func(t *testing.T) {
		for i := 0; i < 50; i++ {
			key, err := GenerateAccessKey(accessKeyMaxLen, nil)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			for _, r := range key {
				if !strings.ContainsRune(alphaNumericTable, r) {
					t.Fatalf("key %q contains character %q outside the alphanumeric table", key, r)
				}
			}
			if ContainsReservedChars(key) {
				t.Fatalf("key %q contains reserved characters", key)
			}
		}
	})

	t.Run("deterministic reader", func(t *testing.T) {
		testCases := []struct {
			b        byte
			expected byte
		}{
			{0, '0'},
			{9, '9'},
			{10, 'A'},
			{35, 'Z'},
			{36, '0'}, // wraps around the table
			{255, alphaNumericTable[255%int(alphaNumericTableLen)]},
		}
		for _, tc := range testCases {
			r := bytes.NewReader(bytes.Repeat([]byte{tc.b}, accessKeyMinLen))
			key, err := GenerateAccessKey(accessKeyMinLen, r)
			if err != nil {
				t.Fatalf("byte %d: unexpected error: %v", tc.b, err)
			}
			if key != strings.Repeat(string(tc.expected), accessKeyMinLen) {
				t.Fatalf("byte %d: got %q, want %q", tc.b, key, strings.Repeat(string(tc.expected), accessKeyMinLen))
			}
		}
	})

	t.Run("reader errors", func(t *testing.T) {
		if _, err := GenerateAccessKey(accessKeyMaxLen, strings.NewReader("")); !errors.Is(err, io.EOF) {
			t.Fatalf("empty reader: got %v, want io.EOF", err)
		}
		if _, err := GenerateAccessKey(accessKeyMaxLen, strings.NewReader("abc")); !errors.Is(err, io.ErrUnexpectedEOF) {
			t.Fatalf("short reader: got %v, want io.ErrUnexpectedEOF", err)
		}
		boom := errors.New("boom")
		if _, err := GenerateAccessKey(accessKeyMaxLen, iotest.ErrReader(boom)); !errors.Is(err, boom) {
			t.Fatalf("failing reader: got %v, want %v", err, boom)
		}
	})
}

func TestGenerateSecretKey(t *testing.T) {
	t.Run("default length", func(t *testing.T) {
		for _, length := range []int{0, -1} {
			key, err := GenerateSecretKey(length, nil)
			if err != nil {
				t.Fatalf("length %d: unexpected error: %v", length, err)
			}
			if len(key) != secretKeyMaxLen {
				t.Fatalf("length %d: got key length %d, want %d", length, len(key), secretKeyMaxLen)
			}
		}
	})

	t.Run("explicit lengths", func(t *testing.T) {
		// Lengths that are a multiple of 4 round-trip exactly through
		// raw base64 encoding.
		for _, length := range []int{secretKeyMinLen, 12, secretKeyMaxLen, 64} {
			key, err := GenerateSecretKey(length, nil)
			if err != nil {
				t.Fatalf("length %d: unexpected error: %v", length, err)
			}
			if len(key) != length {
				t.Fatalf("length %d: got key length %d", length, len(key))
			}
			if !IsSecretKeyValid(key) {
				t.Fatalf("length %d: generated key is not valid", length)
			}
		}
	})

	t.Run("too short", func(t *testing.T) {
		for _, length := range []int{1, secretKeyMinLen - 1} {
			if _, err := GenerateSecretKey(length, nil); err == nil {
				t.Fatalf("length %d: expected error, got nil", length)
			}
		}
	})

	t.Run("charset", func(t *testing.T) {
		const allowed = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+"
		for i := 0; i < 50; i++ {
			key, err := GenerateSecretKey(secretKeyMaxLen, nil)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if strings.ContainsAny(key, "/=") {
				t.Fatalf("key %q contains '/' or '='", key)
			}
			for _, r := range key {
				if !strings.ContainsRune(allowed, r) {
					t.Fatalf("key %q contains unexpected character %q", key, r)
				}
			}
		}
	})

	t.Run("slash is replaced", func(t *testing.T) {
		// 0xff bytes encode to "////..." in standard base64, which must be
		// rewritten to '+' so the secret stays safe for use in URLs/paths.
		r := bytes.NewReader(bytes.Repeat([]byte{0xff}, 64))
		key, err := GenerateSecretKey(secretKeyMinLen, r)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if key != strings.Repeat("+", secretKeyMinLen) {
			t.Fatalf("got %q, want %q", key, strings.Repeat("+", secretKeyMinLen))
		}
	})

	t.Run("reader errors", func(t *testing.T) {
		if _, err := GenerateSecretKey(secretKeyMaxLen, strings.NewReader("")); !errors.Is(err, io.EOF) {
			t.Fatalf("empty reader: got %v, want io.EOF", err)
		}
		if _, err := GenerateSecretKey(secretKeyMaxLen, strings.NewReader("abc")); !errors.Is(err, io.ErrUnexpectedEOF) {
			t.Fatalf("short reader: got %v, want io.ErrUnexpectedEOF", err)
		}
	})
}

func TestGenerateCredentials(t *testing.T) {
	seen := make(map[string]struct{})
	for i := 0; i < 20; i++ {
		ak, sk, err := GenerateCredentials()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(ak) != accessKeyMaxLen {
			t.Fatalf("access key length: got %d, want %d", len(ak), accessKeyMaxLen)
		}
		if len(sk) != secretKeyMaxLen {
			t.Fatalf("secret key length: got %d, want %d", len(sk), secretKeyMaxLen)
		}
		if _, dup := seen[ak+sk]; dup {
			t.Fatalf("duplicate credentials generated: %s", ak)
		}
		seen[ak+sk] = struct{}{}
	}
}

func TestCreateNewCredentialsWithMetadata(t *testing.T) {
	ak := alphaNumericTable[:accessKeyMinLen]
	sk := alphaNumericTable[:secretKeyMinLen]
	long := strings.Repeat("x", 100)

	t.Run("length validation", func(t *testing.T) {
		testCases := []struct {
			name string
			ak   string
			sk   string
			err  error
		}{
			{"short access key", ak[:accessKeyMinLen-1], sk, ErrInvalidAccessKeyLength},
			{"long access key", long[:accessKeyMaxLen+1], sk, ErrInvalidAccessKeyLength},
			{"short secret key", ak, sk[:secretKeyMinLen-1], ErrInvalidSecretKeyLength},
			{"long secret key", ak, long[:secretKeyMaxLen+1], ErrInvalidSecretKeyLength},
			{"max access key", long[:accessKeyMaxLen], sk, nil},
			{"max secret key", ak, long[:secretKeyMaxLen], nil},
		}
		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				cred, err := CreateNewCredentialsWithMetadata(tc.ak, tc.sk, map[string]any{}, "")
				if !errors.Is(err, tc.err) {
					t.Fatalf("error: got %v, want %v", err, tc.err)
				}
				if err != nil && !reflect.DeepEqual(cred, Credentials{}) {
					t.Fatalf("expected empty credentials on error, got %+v", cred)
				}
			})
		}
	})

	t.Run("without token secret", func(t *testing.T) {
		m := map[string]any{"exp": time.Now().Add(time.Hour).Unix()}
		cred, err := CreateNewCredentialsWithMetadata(ak, sk, m, "")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if cred.AccessKey != ak || cred.SecretKey != sk {
			t.Fatalf("keys not copied: %+v", cred)
		}
		if cred.Status != AccountOn {
			t.Fatalf("status: got %q, want %q", cred.Status, AccountOn)
		}
		if cred.SessionToken != "" {
			t.Fatalf("expected no session token, got %q", cred.SessionToken)
		}
		if !cred.Expiration.Equal(timeSentinel) {
			t.Fatalf("expiration: got %v, want sentinel %v", cred.Expiration, timeSentinel)
		}
		if cred.IsTemp() || cred.IsExpired() || !cred.IsValid() {
			t.Fatalf("expected a valid permanent credential, got %+v", cred)
		}
		if _, ok := m["accessKey"]; ok {
			t.Fatal("claims map must not be modified when no token is generated")
		}
	})

	t.Run("with token secret", func(t *testing.T) {
		const tokenSecret = "a-token-secret"
		exp := time.Now().UTC().Add(time.Hour).Truncate(time.Second)
		m := map[string]any{"exp": exp.Unix(), "parent": "someone"}

		cred, err := CreateNewCredentialsWithMetadata(ak, sk, m, tokenSecret)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if cred.Status != AccountOn {
			t.Fatalf("status: got %q, want %q", cred.Status, AccountOn)
		}
		if !cred.Expiration.Equal(exp) {
			t.Fatalf("expiration: got %v, want %v", cred.Expiration, exp)
		}
		if cred.Expiration.Location() != time.UTC {
			t.Fatalf("expiration must be UTC, got %v", cred.Expiration.Location())
		}
		if cred.SessionToken == "" {
			t.Fatal("expected a session token")
		}
		if !cred.IsTemp() || !cred.IsValid() {
			t.Fatalf("expected a valid temporary credential, got %+v", cred)
		}

		claims, err := ExtractClaims(cred.SessionToken, tokenSecret)
		if err != nil {
			t.Fatalf("ExtractClaims: %v", err)
		}
		if got := claims.AccessKey; got != ak {
			t.Fatalf("token access key: got %q, want %q", got, ak)
		}
		if got, _ := claims.Lookup("parent"); got != "someone" {
			t.Fatalf("token parent claim: got %q, want %q", got, "someone")
		}
		gotExp, err := ExpToInt64(claims.Map()["exp"])
		if err != nil {
			t.Fatalf("ExpToInt64 on token exp: %v", err)
		}
		if gotExp != exp.Unix() {
			t.Fatalf("token exp: got %d, want %d", gotExp, exp.Unix())
		}
		if _, err := ExtractClaims(cred.SessionToken, "wrong-secret"); err == nil {
			t.Fatal("expected signature verification to fail with a wrong secret")
		}
	})

	t.Run("with token secret but no exp", func(t *testing.T) {
		cred, err := CreateNewCredentialsWithMetadata(ak, sk, map[string]any{}, "secret")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		// A missing exp resolves to the unix epoch, which is the sentinel
		// meaning "never expires".
		if !cred.Expiration.Equal(timeSentinel) {
			t.Fatalf("expiration: got %v, want sentinel", cred.Expiration)
		}
		if cred.SessionToken == "" {
			t.Fatal("expected a session token")
		}
		if cred.IsTemp() || cred.IsExpired() || !cred.IsValid() {
			t.Fatalf("expected a valid non-temporary credential, got %+v", cred)
		}
	})

	t.Run("invalid exp", func(t *testing.T) {
		for _, exp := range []any{-1, "not-a-number", true} {
			cred, err := CreateNewCredentialsWithMetadata(ak, sk, map[string]any{"exp": exp}, "secret")
			if err == nil {
				t.Fatalf("exp %v: expected an error", exp)
			}
			if cred.SessionToken != "" {
				t.Fatalf("exp %v: no session token should be issued, got %q", exp, cred.SessionToken)
			}
		}
	})
}

func TestGetNewCredentialsWithMetadata(t *testing.T) {
	const tokenSecret = "another-secret"
	exp := time.Now().UTC().Add(30 * time.Minute).Truncate(time.Second)
	cred, err := GetNewCredentialsWithMetadata(map[string]any{"exp": exp.Unix()}, tokenSecret)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(cred.AccessKey) != accessKeyMaxLen || len(cred.SecretKey) != secretKeyMaxLen {
		t.Fatalf("unexpected key lengths: %d/%d", len(cred.AccessKey), len(cred.SecretKey))
	}
	if !cred.IsTemp() || !cred.IsValid() {
		t.Fatalf("expected valid temporary credentials, got %+v", cred)
	}
	claims, err := ExtractClaims(cred.SessionToken, tokenSecret)
	if err != nil {
		t.Fatalf("ExtractClaims: %v", err)
	}
	if claims.AccessKey != cred.AccessKey {
		t.Fatalf("token access key %q does not match credential %q", claims.AccessKey, cred.AccessKey)
	}
}

func TestJWTSignWithAccessKey(t *testing.T) {
	const secret = "jwt-secret"
	m := map[string]any{
		"exp":    time.Now().UTC().Add(time.Hour).Unix(),
		"custom": "value",
	}
	token, err := JWTSignWithAccessKey("myaccesskey", m, secret)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got := m["accessKey"]; got != "myaccesskey" {
		t.Fatalf("accessKey claim was not injected into the map: %v", got)
	}
	if strings.Count(token, ".") != 2 {
		t.Fatalf("token %q is not a compact JWS", token)
	}

	claims, err := ExtractClaims(token, secret)
	if err != nil {
		t.Fatalf("ExtractClaims: %v", err)
	}
	if claims.AccessKey != "myaccesskey" {
		t.Fatalf("access key: got %q, want %q", claims.AccessKey, "myaccesskey")
	}
	if got, _ := claims.Lookup("custom"); got != "value" {
		t.Fatalf("custom claim: got %q, want %q", got, "value")
	}

	// The same claims signed again must verify and carry the same payload.
	token2, err := JWTSignWithAccessKey("myaccesskey", m, secret)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if token2 != token {
		t.Fatalf("signing identical claims should be deterministic for HS512")
	}
}

func TestExtractClaims(t *testing.T) {
	const secret = "extract-secret"
	validToken, err := JWTSignWithAccessKey("ak", map[string]any{"exp": time.Now().UTC().Add(time.Hour).Unix()}, secret)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	t.Run("empty arguments", func(t *testing.T) {
		for _, tc := range []struct{ token, secret string }{
			{"", ""},
			{"", secret},
			{validToken, ""},
		} {
			if _, err := ExtractClaims(tc.token, tc.secret); err == nil {
				t.Fatalf("token=%q secret=%q: expected an error", tc.token, tc.secret)
			}
		}
	})

	t.Run("valid", func(t *testing.T) {
		claims, err := ExtractClaims(validToken, secret)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if claims == nil || claims.AccessKey != "ak" {
			t.Fatalf("unexpected claims: %+v", claims)
		}
	})

	t.Run("wrong secret", func(t *testing.T) {
		if _, err := ExtractClaims(validToken, "not-the-secret"); err == nil {
			t.Fatal("expected a signature error")
		}
	})

	t.Run("expired", func(t *testing.T) {
		expired, err := JWTSignWithAccessKey("ak", map[string]any{"exp": time.Now().UTC().Add(-time.Hour).Unix()}, secret)
		if err != nil {
			t.Fatalf("sign: %v", err)
		}
		if _, err := ExtractClaims(expired, secret); err == nil {
			t.Fatal("expected an expiry error")
		}
	})

	t.Run("missing access key claim", func(t *testing.T) {
		// Sign directly with the library to avoid the accessKey injection
		// performed by JWTSignWithAccessKey.
		token := signRaw(t, map[string]any{"exp": time.Now().UTC().Add(time.Hour).Unix()}, secret)
		if _, err := ExtractClaims(token, secret); err == nil {
			t.Fatal("expected an error for a token without accessKey/sub")
		}
	})

	t.Run("sub is accepted in place of accessKey", func(t *testing.T) {
		token := signRaw(t, map[string]any{"sub": "subject", "exp": time.Now().UTC().Add(time.Hour).Unix()}, secret)
		claims, err := ExtractClaims(token, secret)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if claims.AccessKey != "subject" {
			t.Fatalf("access key: got %q, want %q", claims.AccessKey, "subject")
		}
	})

	t.Run("malformed tokens", func(t *testing.T) {
		parts := strings.Split(validToken, ".")
		for name, token := range map[string]string{
			"garbage":           "not-a-jwt",
			"two parts":         parts[0] + "." + parts[1],
			"four parts":        validToken + ".extra",
			"empty signature":   parts[0] + "." + parts[1] + ".",
			"tampered payload":  parts[0] + "." + parts[1] + "x." + parts[2],
			"tampered sig":      parts[0] + "." + parts[1] + "." + parts[2][:len(parts[2])-2] + "AA",
			"non-base64 header": "!!!." + parts[1] + "." + parts[2],
		} {
			if _, err := ExtractClaims(token, secret); err == nil {
				t.Fatalf("%s: expected an error for token %q", name, token)
			}
		}
	})
}

func TestDefaultAndAnonymousCredentials(t *testing.T) {
	if DefaultCredentials.AccessKey != DefaultAccessKey || DefaultCredentials.SecretKey != DefaultSecretKey {
		t.Fatalf("DefaultCredentials does not match the default keys: %+v", DefaultCredentials)
	}
	if !DefaultCredentials.IsValid() {
		t.Fatal("DefaultCredentials should be valid")
	}
	if !reflect.DeepEqual(AnonymousCredentials, Credentials{}) {
		t.Fatalf("AnonymousCredentials should be the zero value, got %+v", AnonymousCredentials)
	}
	if AnonymousCredentials.IsValid() {
		t.Fatal("AnonymousCredentials should not be valid")
	}
}

func TestCredentialsJSONRoundTrip(t *testing.T) {
	exp := time.Date(2031, time.May, 6, 7, 8, 9, 0, time.UTC)
	in := Credentials{
		AccessKey:    "accesskey",
		SecretKey:    "secretkey1",
		SessionToken: "token",
		Expiration:   exp,
		Status:       AccountOn,
		ParentUser:   "parent",
		Groups:       []string{"g1", "g2"},
		Claims:       map[string]any{iamPolicyClaimNameSA: "inherited-policy"},
		Name:         "name",
		Description:  "desc",
	}
	data, err := json.Marshal(in)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var out Credentials
	if err := json.Unmarshal(data, &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if out.AccessKey != in.AccessKey || out.SecretKey != in.SecretKey || out.SessionToken != in.SessionToken ||
		!out.Expiration.Equal(in.Expiration) || out.Status != in.Status || out.ParentUser != in.ParentUser ||
		out.Name != in.Name || out.Description != in.Description || len(out.Groups) != 2 {
		t.Fatalf("round trip mismatch:\n in=%+v\nout=%+v", in, out)
	}
	if !out.IsServiceAccount() || !out.IsImpliedPolicy() {
		t.Fatalf("service account claims lost in round trip: %+v", out.Claims)
	}
	if strings.Contains(string(data), `"comment"`) {
		t.Fatalf("empty deprecated comment field should be omitted: %s", data)
	}
}

// signRaw signs the given claims with HS512 without any of the claim
// rewriting done by JWTSignWithAccessKey.
func signRaw(t *testing.T, m map[string]any, secret string) string {
	t.Helper()
	token, err := jwtgo.NewWithClaims(jwtgo.SigningMethodHS512, jwtgo.MapClaims(m)).SignedString([]byte(secret))
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return token
}
