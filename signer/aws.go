package signer

import (
	"errors"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/kms"
)

type SigningAlgorithm string

const (
	SigningAlgorithmEcdsaSha256 SigningAlgorithm = "ECDSA_SHA_256"
	SigningAlgorithmEcdsaSha384 SigningAlgorithm = "ECDSA_SHA_384"
	SigningAlgorithmEcdsaSha512 SigningAlgorithm = "ECDSA_SHA_512"
)

type AwsKmsIssuerSigner struct {
	KmsKeyId         string
	KmsConfig        *aws.Config
	PublicKeyUrl     string
	SigningAlgorithm SigningAlgorithm
}

func (s *AwsKmsIssuerSigner) GetKeyUrl() (string, error) {
	return s.PublicKeyUrl, nil
}

func (s *AwsKmsIssuerSigner) Sign(message []byte) ([]byte, error) {
	sess, _ := session.NewSession(s.KmsConfig)
	svc := kms.New(sess)

	//---

	// If the SigningAlgorithm has not been set, we'll attempt to determine it.
	if len(s.SigningAlgorithm) == 0 {
		input := &kms.DescribeKeyInput{
			KeyId: aws.String(s.KmsKeyId),
		}

		result, err := svc.DescribeKey(input)
		if err != nil {
			return []byte{}, err
		}

		if len(result.KeyMetadata.SigningAlgorithms) < 1 || len(result.KeyMetadata.SigningAlgorithms) > 1 {
			return []byte{}, errors.New("unable to automatically determine correct signing algorithm")
		}

		s.SigningAlgorithm = SigningAlgorithm(*result.KeyMetadata.SigningAlgorithms[0])
	}

	//---

	input := &kms.SignInput{
		KeyId:            aws.String(s.KmsKeyId),
		Message:          message,
		MessageType:      aws.String("RAW"),
		SigningAlgorithm: aws.String(string(s.SigningAlgorithm)),
	}

	result, err := svc.Sign(input)
	if err != nil {
		return []byte{}, err
	}

	return result.Signature, nil
}
