package signer

import (
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/kms"
)

type AwsKmsIssuerSigner struct {
	KmsKeyId     string
	KmsConfig    *aws.Config
	PublicKeyUrl string
}

func (s *AwsKmsIssuerSigner) GetKeyUrl() (string, error) {
	return s.PublicKeyUrl, nil
}

func (s *AwsKmsIssuerSigner) Sign(der []byte) ([]byte, error) {
	sess, _ := session.NewSession(s.KmsConfig)
	svc := kms.New(sess)

	input := &kms.SignInput{
		KeyId:            aws.String(s.KmsKeyId),
		Message:          der,
		MessageType:      aws.String("RAW"),
		SigningAlgorithm: aws.String("ECDSA_SHA_256"),
	}

	result, err := svc.Sign(input)
	if err != nil {
		return []byte{}, err
	}

	return result.Signature, nil
}
