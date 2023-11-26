package signer

import (
	"context"
	"errors"
	"fmt"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
)

const (
	// Map the three allowed Signing Algorithms here so they're available directly from this package.

	SigningAlgorithmSpecEcdsaSha256 = types.SigningAlgorithmSpecEcdsaSha256
	SigningAlgorithmSpecEcdsaSha384 = types.SigningAlgorithmSpecEcdsaSha384
	SigningAlgorithmSpecEcdsaSha512 = types.SigningAlgorithmSpecEcdsaSha512
)

type AwsKmsIssuerSigner struct {
	KmsKeyId         string
	Client           *kms.Client
	PublicKeyUrl     string
	SigningAlgorithm types.SigningAlgorithmSpec
}

func (s *AwsKmsIssuerSigner) GetKeyUrl() (string, error) {
	return s.PublicKeyUrl, nil
}

func (s *AwsKmsIssuerSigner) Sign(message []byte) ([]byte, error) {

	// If the SigningAlgorithm has not been set, we'll attempt to determine it.
	if len(s.SigningAlgorithm) == 0 {

		result, err := s.Client.DescribeKey(context.TODO(), &kms.DescribeKeyInput{
			KeyId: &s.KmsKeyId,
		})
		if err != nil {
			return []byte{}, err
		}

		if len(result.KeyMetadata.SigningAlgorithms) < 1 || len(result.KeyMetadata.SigningAlgorithms) > 1 {
			return []byte{}, errors.New("unable to automatically determine correct signing algorithm")
		}

		s.SigningAlgorithm = result.KeyMetadata.SigningAlgorithms[0]
	}

	//---

	switch s.SigningAlgorithm {
	case SigningAlgorithmSpecEcdsaSha256:
	case SigningAlgorithmSpecEcdsaSha384:
	case SigningAlgorithmSpecEcdsaSha512:
	default:
		return nil, fmt.Errorf(
			"unsupported signing algorithm. Supported: ECDSA_SHA_256, ECDSA_SHA_384 & ECDSA_SHA_512. Found: %s",
			s.SigningAlgorithm,
		)
	}

	//---

	result, err := s.Client.Sign(context.TODO(), &kms.SignInput{
		KeyId:            &s.KmsKeyId,
		Message:          message,
		MessageType:      types.MessageTypeRaw,
		SigningAlgorithm: s.SigningAlgorithm,
	})
	if err != nil {
		return []byte{}, err
	}

	return result.Signature, nil
}
