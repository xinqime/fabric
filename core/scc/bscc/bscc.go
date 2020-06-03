/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

// Package cscc chaincode configer provides functions to manage
// configuration transactions as the network is being reconfigured. The
// configuration transactions arrive from the ordering service to the committer
// who calls this chaincode. The chaincode also provides peer configuration
// services such as joining a chain or getting configuration data.
package bscc

import (
	"bytes"
	"fmt"
	"github.com/golang/protobuf/proto"
	"github.com/hyperledger/fabric/common/channelconfig"
	"github.com/hyperledger/fabric/common/config"
	"github.com/hyperledger/fabric/common/flogging"
	"github.com/hyperledger/fabric/core/aclmgmt"
	"github.com/hyperledger/fabric/core/chaincode/shim"
	"github.com/hyperledger/fabric/core/common/ccprovider"
	"github.com/hyperledger/fabric/core/common/sysccprovider"
	"github.com/hyperledger/fabric/core/peer"
	"github.com/hyperledger/fabric/core/policy"
	"github.com/hyperledger/fabric/msp/mgmt"
	"github.com/hyperledger/fabric/protos/common"
	"github.com/hyperledger/fabric/protos/msp"
	pb "github.com/hyperledger/fabric/protos/peer"
	"github.com/hyperledger/fabric/protos/utils"
	"github.com/pkg/errors"
)

// New creates a new instance of the CSCC.
// Typically, only one will be created per peer instance.
func New(ccp ccprovider.ChaincodeProvider, sccp sysccprovider.SystemChaincodeProvider, aclProvider aclmgmt.ACLProvider) *PeerConfiger {
	return &PeerConfiger{
		policyChecker: policy.NewPolicyChecker(
			peer.NewChannelPolicyManagerGetter(),
			mgmt.GetLocalMSP(),
			mgmt.NewLocalMSPPrincipalGetter(),
		),
		configMgr:   peer.NewConfigSupport(),
		ccp:         ccp,
		sccp:        sccp,
		aclProvider: aclProvider,
	}
}

func (e *PeerConfiger) Name() string              { return "bscc" }
func (e *PeerConfiger) Path() string              { return "github.com/hyperledger/fabric/core/scc/bscc" }
func (e *PeerConfiger) InitArgs() [][]byte        { return nil }
func (e *PeerConfiger) Chaincode() shim.Chaincode { return e }
func (e *PeerConfiger) InvokableExternal() bool   { return true }
func (e *PeerConfiger) InvokableCC2CC() bool      { return false }
func (e *PeerConfiger) Enabled() bool             { return true }

// PeerConfiger implements the configuration handler for the peer. For every
// configuration transaction coming in from the ordering service, the
// committer calls this system chaincode to process the transaction.
type PeerConfiger struct {
	policyChecker policy.PolicyChecker
	configMgr     config.Manager
	ccp           ccprovider.ChaincodeProvider
	sccp          sysccprovider.SystemChaincodeProvider
	aclProvider   aclmgmt.ACLProvider
}

var bsclogger = flogging.MustGetLogger("bscc")

// These are function names from Invoke first parameter
const (
	Set                string = "Set"
)

// Init is mostly useless from an SCC perspective
func (e *PeerConfiger) Init(stub shim.ChaincodeStubInterface) pb.Response {
	bsclogger.Info("Init BSCC")
	return shim.Success(nil)
}

// Invoke is called for the following:
// # to process joining a chain (called by app as a transaction proposal)
// # to get the current configuration block (called by app)
// # to update the configuration block (called by committer)
// Peer calls this function with 2 arguments:
// # args[0] is the function name, which must be JoinChain, GetConfigBlock or
// UpdateConfigBlock
// # args[1] is a configuration Block if args[0] is JoinChain or
// UpdateConfigBlock; otherwise it is the chain id
// TODO: Improve the scc interface to avoid marshal/unmarshal args
func (e *PeerConfiger) Invoke(stub shim.ChaincodeStubInterface) pb.Response {
	args := stub.GetArgs()

	if len(args) < 1 {
		return shim.Error(fmt.Sprintf("Incorrect number of arguments, %d", len(args)))
	}

	fname := string(args[0])
	var result string
	var err error

	creatorByte, err := stub.GetCreator()
	// 构造SerializedIdentity方法，并将creator进行Unmarshal
	si := &msp.SerializedIdentity{}
	err = proto.Unmarshal(creatorByte, si)
	if err != nil {
		return shim.Error(err.Error())
	}

	bsclogger.Info(fmt.Sprintf("cert:, %s", si.GetIdBytes()))

	switch fname {

	case Set:
		if args[1] == nil || args[2] == nil{
			return shim.Error("error args")
		}
		chainID :=stub.GetChannelID()
		bsclogger.Info(fmt.Sprintf("chainID:, %s", chainID))
		adminCert, err := getAdminCert(chainID)
		if err != nil{
			return shim.Error(fmt.Sprint(err))
		}
		bsclogger.Info(fmt.Sprintf("admincert:, %s", adminCert))
		if bytes.Compare(si.GetIdBytes(), adminCert) != 0{
			return shim.Error(fmt.Sprintf("No authority to use SET method"))
		}
		result, err = setData(stub, args)
	}
	if err != nil {
		return shim.Error(err.Error())
	}
	return shim.Success([]byte(result))
	// Handle ACL:
	// 1. get the signed proposal
}
// Return the current configuration block for the specified chainID. If the
// peer doesn't belong to the chain, return error
func getAdminCert(chainID string) ([]byte, error) {
	if len(chainID) == 0 {
		return nil, errors.New("chainID is nil")
	}
	targetLedger := peer.GetLedger(chainID)
	if targetLedger == nil {
		return nil,errors.New(fmt.Sprintf("Invalid chain ID, %s", chainID))
	}
	block, err := targetLedger.GetBlockByNumber(0)
	if block == nil {
		return nil, errors.New("block is nil")
	}
	if err := validateConfigBlock(block); err != nil {
		return nil, err
	}
	adminCert, mspId, err := utils.GetCertFromBlock(block)
	bsclogger.Info(fmt.Sprintf("mspid:, %s", mspId))
	if err != nil {
		return nil, errors.WithStack(err)
	}

	return adminCert, nil
}

// joinChain will join the specified chain in the configuration block.
// Since it is the first block, it is the genesis block containing configuration
// for this chain, so we want to update the Chain object with this info
func setData(stub shim.ChaincodeStubInterface, args [][]byte) (string, error) {

	err := stub.PutState(string(args[1]), args[2])
	if err != nil {
		return "", err
	}
	return "{\"success\": \"true\", \"msg\":\"充值成功\"}", nil
}

// validateConfigBlock validate configuration block to see whenever it's contains valid config transaction
func validateConfigBlock(block *common.Block) error {
	envelopeConfig, err := utils.ExtractEnvelope(block, 0)
	if err != nil {
		return errors.Errorf("Failed to %s", err)
	}

	configEnv := &common.ConfigEnvelope{}
	_, err = utils.UnmarshalEnvelopeOfType(envelopeConfig, common.HeaderType_CONFIG, configEnv)
	if err != nil {
		return errors.Errorf("Bad configuration envelope: %s", err)
	}

	if configEnv.Config == nil {
		return errors.New("Nil config envelope Config")
	}

	if configEnv.Config.ChannelGroup == nil {
		return errors.New("Nil channel group")
	}

	if configEnv.Config.ChannelGroup.Groups == nil {
		return errors.New("No channel configuration groups are available")
	}

	_, exists := configEnv.Config.ChannelGroup.Groups[channelconfig.ApplicationGroupKey]
	if !exists {
		return errors.Errorf("Invalid configuration block, missing %s "+
			"configuration group", channelconfig.ApplicationGroupKey)
	}

	return nil
}



