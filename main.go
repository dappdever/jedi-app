package main

import (
//	"testing"
	"bytes"
	"fmt"
	"context"
	"time"
	"github.com/ucbrise/jedi-protocol-go"
	"github.com/ucbrise/jedi-pairing/lang/go/wkdibe"
)

const TestPatternSize = 20
var TestHierarchy = []byte("testHierarchy")
const quote1 = "Give me liberty or give me death. -- Patrick Henry"
const quote2 = "Chancellor on the brink of second bailout for bank --Time of London"

type TestPublicInfo struct {
       params *wkdibe.Params
}

func (tpi *TestPublicInfo) ParamsForHierarchy(ctx context.Context, hierarchy []byte) (*wkdibe.Params, error) {
        return tpi.params, nil
}

type TestKeyStore struct {
	params *wkdibe.Params
	master *wkdibe.MasterKey
}

func NewTestKeyStore() (*TestPublicInfo, *TestKeyStore) {
       tks := new(TestKeyStore)
       tks.params, tks.master = wkdibe.Setup(TestPatternSize, true)
       tpi := new(TestPublicInfo)
       tpi.params = tks.params
       return tpi, tks
}

func (tks *TestKeyStore) KeyForPattern(ctx context.Context, hierarchy []byte, pattern jedi.Pattern) (*wkdibe.Params, *wkdibe.SecretKey, error) {
       empty := make(jedi.Pattern, TestPatternSize)
       return tks.params, wkdibe.KeyGen(tks.params, tks.master, empty.ToAttrs()), nil
}

func NewTestState() *jedi.ClientState {
	info, store := NewTestKeyStore()
	encoder := jedi.NewDefaultPatternEncoder(TestPatternSize - jedi.MaxTimeLength)
	return jedi.NewClientState(info, store, encoder, 1<<20)
}

func testMessageTransfer(state *jedi.ClientState, hierarchy []byte, uri string, timestamp time.Time, message string) {
	var err error
	ctx := context.Background()

	 fmt.Println ("Original message  : ", message)

	var encrypted []byte
	if encrypted, err = state.Encrypt(ctx, hierarchy, uri, timestamp, []byte(message)); err != nil {
		panic(fmt.Errorf("cannot encrypt: %s", err))
	}

	var decrypted []byte
	if decrypted, err = state.Decrypt(ctx, hierarchy, uri, timestamp, encrypted); err != nil {
		panic(fmt.Errorf("cannot decrypt: %s", err))

	}
        
	fmt.Println ("Decrypted message  : ", string(decrypted))

	if !bytes.Equal(decrypted, []byte(message)) {
		panic("Original and decrypted messages differ")
	}
}


func main () {
	state := NewTestState()
	now := time.Now()

	testMessageTransfer(state, TestHierarchy, "a/b/c", now, quote1)

	params, masterKey := wkdibe.Setup(3, true)

	fmt.Println("params: ", params)
	fmt.Println("masterKey: ", masterKey)
}
