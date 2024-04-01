// Copyright 2021 The Sigstore Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package rekor

import (
	"context"
	"crypto"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
	"os"

	"github.com/sigstore/cosign/v2/internal/pkg/cosign"
	cosignv1 "github.com/sigstore/cosign/v2/pkg/cosign"
	cbundle "github.com/sigstore/cosign/v2/pkg/cosign/bundle"
	"github.com/sigstore/cosign/v2/pkg/oci"
	"github.com/sigstore/cosign/v2/pkg/oci/mutate"

	"github.com/sigstore/rekor/pkg/generated/client"
	"github.com/sigstore/rekor/pkg/generated/models"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
)

type tlogUploadFn func(*client.Rekor, []byte) (*models.LogEntryAnon, error)

func uploadToTlog(rekorBytes []byte, rClient *client.Rekor, upload tlogUploadFn) (*cbundle.RekorBundle, error) {
	fmt.Println("Entered uploadToTlog function")
	entry, err := upload(rClient, rekorBytes)
	if err != nil {
		fmt.Println("Error while uploading to tlog : ", err)
		return nil, err
	}
	fmt.Fprintln(os.Stderr, "tlog entry created with index:", *entry.LogIndex)
	return cbundle.EntryToBundle(entry), nil
}

// signerWrapper calls a wrapped, inner signer then uploads either the Cert or Pub(licKey) of the results to Rekor, then adds the resulting `Bundle`
type signerWrapper struct {
	inner cosign.Signer

	rClient *client.Rekor
}

var _ cosign.Signer = (*signerWrapper)(nil)

// Sign implements `cosign.Signer`
func (rs *signerWrapper) Sign(ctx context.Context, payload io.Reader) (oci.Signature, crypto.PublicKey, error) {
	fmt.Println("Entered signerWrapper - Sign function")
	sig, pub, err := rs.inner.Sign(ctx, payload)
	if err != nil {
		fmt.Println("Error in inner signer : ", err)
		return nil, nil, err
	}

	pubkey, _ := cryptoutils.MarshalPublicKeyToPEM(pub)
	fmt.Println("Public Key after signing: ", string(pubkey))

	payloadBytes, err := sig.Payload()
	if err != nil {
		return nil, nil, err
	}
	b64Sig, err := sig.Base64Signature()
	if err != nil {
		return nil, nil, err
	}
	sigBytes, err := base64.StdEncoding.DecodeString(b64Sig)
	if err != nil {
		return nil, nil, err
	}

	// Upload the cert or the public key, depending on what we have
	cert, err := sig.Cert()
	if err != nil {
		return nil, nil, err
	}
	// cert = nil

	var rekorBytes []byte
	if cert != nil {
		rekorBytes, err = cryptoutils.MarshalCertificateToPEM(cert)
		fmt.Println("string of rekorbytes is the certificate :", string(rekorBytes))
	} else {
		rekorBytes, err = cryptoutils.MarshalPublicKeyToPEM(pub)
	}
	if err != nil {
		return nil, nil, err
	}

	bundle, err := uploadToTlog(rekorBytes, rs.rClient, func(r *client.Rekor, b []byte) (*models.LogEntryAnon, error) {
		checkSum := sha256.New()
		if _, err := checkSum.Write(payloadBytes); err != nil {
			fmt.Println("Error while writing checksum : ", err)
			return nil, err
		}
		return cosignv1.TLogUpload(ctx, r, sigBytes, checkSum, b)
	})
	if err != nil {
		return nil, nil, err
	}

	fmt.Println("Are we here yet?")

	newSig, err := mutate.Signature(sig, mutate.WithBundle(bundle))
	if err != nil {
		return nil, nil, err
	}

	return newSig, pub, nil
}

// NewSigner returns a `cosign.Signer` which uploads the signature to Rekor
func NewSigner(inner cosign.Signer, rClient *client.Rekor) cosign.Signer {
	return &signerWrapper{
		inner:   inner,
		rClient: rClient,
	}
}