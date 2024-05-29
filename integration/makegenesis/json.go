package makegenesis

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"time"

	"github.com/Fantom-foundation/go-opera/inter"
	"github.com/Fantom-foundation/go-opera/inter/drivertype"
	"github.com/Fantom-foundation/go-opera/inter/iblockproc"
	"github.com/Fantom-foundation/go-opera/inter/ier"
	"github.com/Fantom-foundation/go-opera/inter/validatorpk"
	"github.com/Fantom-foundation/go-opera/opera"
	"github.com/Fantom-foundation/go-opera/opera/contracts/driver"
	"github.com/Fantom-foundation/go-opera/opera/contracts/driver/drivercall"
	"github.com/Fantom-foundation/go-opera/opera/contracts/driverauth"
	"github.com/Fantom-foundation/go-opera/opera/contracts/evmwriter"
	nativeminter "github.com/Fantom-foundation/go-opera/opera/contracts/minter"
	"github.com/Fantom-foundation/go-opera/opera/contracts/netinit"
	netinitcall "github.com/Fantom-foundation/go-opera/opera/contracts/netinit/netinitcalls"
	"github.com/Fantom-foundation/go-opera/opera/contracts/sfc"
	"github.com/Fantom-foundation/go-opera/opera/contracts/sfclib"
	"github.com/Fantom-foundation/go-opera/opera/genesis"
	"github.com/Fantom-foundation/go-opera/opera/genesis/gpos"
	"github.com/Fantom-foundation/go-opera/opera/genesisstore"
	"github.com/Fantom-foundation/lachesis-base/hash"
	"github.com/Fantom-foundation/lachesis-base/inter/idx"
	"github.com/Fantom-foundation/lachesis-base/inter/pos"
	"github.com/Fantom-foundation/lachesis-base/lachesis"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core/types"
)

type GenesisJson struct {
	Rules              NetworkRules
	NetworkInitializer NetworkInitializerParams `json:",omitempty"`
	Accounts           []Account                `json:",omitempty"`
	Validators         []Validator              `json:",omitempty"`
	Txs                []Transaction            `json:",omitempty"`
}

type NetworkInitializerParams struct {
	SealedEpoch      idx.Epoch
	TotalSupply      *big.Int
	MinSelfStake     *big.Int
	SfcAddr          *common.Address
	LibAddr          *common.Address
	DriverAuthAddr   *common.Address
	DriverAddr       *common.Address
	EvmWriterAddr    *common.Address
	NativeMinterAddr *common.Address
	Owner            *common.Address
}

type NetworkRules struct {
	InheritRules        string
	NetworkName         string
	NetworkID           hexutil.Uint64
	DeployEssentials    bool
	GenesisTime         *uint64         `json:",omitempty"`
	MaxBlockGas         *uint64         `json:",omitempty"`
	MaxEpochGas         *uint64         `json:",omitempty"`
	MaxEventGas         *uint64         `json:",omitempty"`
	LongGasAllocPerSec  *uint64         `json:",omitempty"`
	ShortGasAllocPerSec *uint64         `json:",omitempty"`
	Epoch               *uint64         `json:",omitempty"`
	Upgrades            *opera.Upgrades `json:",omitempty"`
}

type Account struct {
	Name    string
	Address common.Address
	Balance *big.Int                    `json:",omitempty"`
	Code    VariableLenCode             `json:",omitempty"`
	Storage map[common.Hash]common.Hash `json:",omitempty"`
}

type Validator struct {
	Name    string
	Address common.Address
	Balance *big.Int
	Stake   *big.Int
	PubKey  string
}

type Transaction struct {
	Name string
	To   common.Address
	Data VariableLenCode `json:",omitempty"`
}

func LoadGenesisJson(filename string) (*GenesisJson, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to read genesis json file; %v", err)
	}
	var decoded GenesisJson
	err = json.Unmarshal(data, &decoded)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal genesis json file; %v", err)
	}
	return &decoded, nil
}

func jsonTxBuilder() func(calldata []byte, addr common.Address) *types.Transaction {
	nonce := uint64(0)
	return func(calldata []byte, addr common.Address) *types.Transaction {
		tx := types.NewTransaction(nonce, addr, common.Big0, 1e10, common.Big0, calldata)
		nonce++
		return tx
	}
}

func ApplyGenesisJson(json *GenesisJson) (*genesisstore.Store, error) {
	builder := NewGenesisBuilder()

	for _, acc := range json.Accounts {
		if acc.Balance != nil {
			builder.AddBalance(acc.Address, acc.Balance)
		}
		if acc.Code != nil {
			builder.SetCode(acc.Address, acc.Code)
		}
		if acc.Storage != nil {
			for key, val := range acc.Storage {
				builder.SetStorage(acc.Address, key, val)
			}
		}
	}

	for _, acc := range json.Validators {
		builder.AddBalance(acc.Address, acc.Balance)
	}

	rules := opera.MainNetRules()

	if json.Rules.InheritRules != "" {
		switch json.Rules.InheritRules {
		case "mainnet":
			rules = opera.MainNetRules()
		case "testnet":
			rules = opera.TestNetRules()
		case "fakenet":
			rules = opera.FakeNetRules()
		default:
			return nil, fmt.Errorf("unknown ruleset to inherit: %s", json.Rules.InheritRules)
		}
	}

	rules.Name = json.Rules.NetworkName
	rules.NetworkID = uint64(json.Rules.NetworkID)
	if json.Rules.MaxBlockGas != nil {
		rules.Blocks.MaxBlockGas = *json.Rules.MaxBlockGas
	}
	if json.Rules.MaxEventGas != nil {
		rules.Economy.Gas.MaxEventGas = *json.Rules.MaxEventGas
	}
	if json.Rules.MaxEpochGas != nil {
		rules.Epochs.MaxEpochGas = *json.Rules.MaxEpochGas
	}
	if json.Rules.ShortGasAllocPerSec != nil {
		rules.Economy.ShortGasPower.AllocPerSec = *json.Rules.ShortGasAllocPerSec
	}
	if json.Rules.LongGasAllocPerSec != nil {
		rules.Economy.LongGasPower.AllocPerSec = *json.Rules.LongGasAllocPerSec
	}

	if json.Rules.DeployEssentials {
		// deploy essential contracts
		// pre deploy NetworkInitializer
		builder.SetCode(netinit.ContractAddress, netinit.GetContractBin())
		// pre deploy NodeDriver
		builder.SetCode(driver.ContractAddress, driver.GetContractBin())
		// pre deploy NodeDriverAuth
		builder.SetCode(driverauth.ContractAddress, driverauth.GetContractBin())
		// pre deploy SFC
		builder.SetCode(sfc.ContractAddress, sfc.GetContractBin())
		// pre deploy SFCLib
		builder.SetCode(sfclib.ContractAddress, sfclib.GetContractBin())
		// pre deploy NativeMinter
		builder.SetCode(nativeminter.ContractAddress, nativeminter.GetContractBin())
		// set non-zero code for pre-compiled contracts
		builder.SetCode(evmwriter.ContractAddress, []byte{0})
	}

	genesisTime := uint64(1)

	if json.Rules.GenesisTime != nil {
		genesisTime = *json.Rules.GenesisTime
	}

	epoch := 1

	if json.Rules.Epoch != nil {
		epoch = int(*json.Rules.Epoch)
	}

	if json.Rules.Upgrades != nil {
		rules.Upgrades = *json.Rules.Upgrades
	}

	builder.SetCurrentEpoch(ier.LlrIdxFullEpochRecord{
		LlrFullEpochRecord: ier.LlrFullEpochRecord{
			BlockState: iblockproc.BlockState{
				LastBlock: iblockproc.BlockCtx{
					Idx:     0,
					Time:    inter.Timestamp(genesisTime),
					Atropos: hash.Event{},
				},
				FinalizedStateRoot:    hash.Hash{},
				EpochGas:              0,
				EpochCheaters:         lachesis.Cheaters{},
				CheatersWritten:       0,
				ValidatorStates:       make([]iblockproc.ValidatorBlockState, 0),
				NextValidatorProfiles: make(map[idx.ValidatorID]drivertype.Validator),
				DirtyRules:            nil,
				AdvanceEpochs:         0,
			},
			EpochState: iblockproc.EpochState{
				Epoch:             idx.Epoch(epoch),
				EpochStart:        inter.Timestamp(genesisTime),
				PrevEpochStart:    inter.Timestamp(genesisTime - 1),
				EpochStateRoot:    hash.Zero,
				Validators:        pos.NewBuilder().Build(),
				ValidatorStates:   make([]iblockproc.ValidatorEpochState, 0),
				ValidatorProfiles: make(map[idx.ValidatorID]drivertype.Validator),
				Rules:             rules,
			},
		},
		Idx: 1,
	})

	blockProc := DefaultBlockProc()
	buildTx := jsonTxBuilder()
	genesisTxs := make(types.Transactions, 0, len(json.Txs))

	sfcAddr := sfc.ContractAddress
	libAddr := sfclib.ContractAddress
	driverAuthAddr := driverauth.ContractAddress
	driverAddr := driver.ContractAddress
	evmWriterAddr := evmwriter.ContractAddress
	nativeMinterAddr := nativeminter.ContractAddress

	if json.NetworkInitializer.SfcAddr != nil {
		sfcAddr = *json.NetworkInitializer.SfcAddr
	}

	if json.NetworkInitializer.LibAddr != nil {
		libAddr = *json.NetworkInitializer.LibAddr
	}

	if json.NetworkInitializer.DriverAuthAddr != nil {
		driverAuthAddr = *json.NetworkInitializer.DriverAuthAddr
	}

	if json.NetworkInitializer.DriverAddr != nil {
		driverAddr = *json.NetworkInitializer.DriverAddr
	}

	if json.NetworkInitializer.EvmWriterAddr != nil {
		evmWriterAddr = *json.NetworkInitializer.EvmWriterAddr
	}

	if json.NetworkInitializer.NativeMinterAddr != nil {
		nativeMinterAddr = *json.NetworkInitializer.NativeMinterAddr
	}

	if json.NetworkInitializer.SealedEpoch != 0 {
		genesisTxs = append(genesisTxs, buildTx(netinitcall.InitializeAll(
			json.NetworkInitializer.SealedEpoch,
			json.NetworkInitializer.TotalSupply,
			json.NetworkInitializer.MinSelfStake,
			sfcAddr,
			libAddr,
			driverAuthAddr,
			driverAddr,
			evmWriterAddr,
			*json.NetworkInitializer.Owner,
			nativeMinterAddr,
		), netinit.ContractAddress))
	}

	for index, validator := range json.Validators {
		pk, err := validatorpk.FromString(validator.PubKey)
		if err != nil {
			return nil, fmt.Errorf("failed to parse validator public key; %v", err)
		}
		setValidatorParams := gpos.Validator{
			ID:               idx.ValidatorID(index + 1),
			Address:          validator.Address,
			PubKey:           pk,
			CreationTime:     inter.Timestamp(time.Now().Unix() * int64(time.Second)),
			CreationEpoch:    0,
			DeactivatedTime:  0,
			DeactivatedEpoch: 0,
			Status:           0,
		}
		genesisTxs = append(genesisTxs, buildTx(drivercall.SetGenesisValidator(setValidatorParams), driver.ContractAddress))
		setDelegationParams := drivercall.Delegation{
			Address:            validator.Address,
			ValidatorID:        idx.ValidatorID(index + 1),
			Stake:              validator.Stake,
			LockedStake:        new(big.Int),
			LockupFromEpoch:    0,
			LockupEndTime:      0,
			LockupDuration:     0,
			EarlyUnlockPenalty: new(big.Int),
			Rewards:            new(big.Int),
		}
		genesisTxs = append(genesisTxs, buildTx(drivercall.SetGenesisDelegation(setDelegationParams), driver.ContractAddress))
	}

	for _, tx := range json.Txs {
		genesisTxs = append(genesisTxs, buildTx(tx.Data, tx.To))
	}

	err := builder.ExecuteGenesisTxs(blockProc, genesisTxs)
	if err != nil {
		return nil, fmt.Errorf("failed to execute json genesis txs; %v", err)
	}

	return builder.Build(genesis.Header{
		GenesisID:   builder.CurrentHash(),
		NetworkID:   uint64(json.Rules.NetworkID),
		NetworkName: json.Rules.NetworkName,
	}), nil
}

type VariableLenCode []byte

func (c *VariableLenCode) MarshalJSON() ([]byte, error) {
	out := make([]byte, hex.EncodedLen(len(*c))+4)
	out[0], out[1], out[2] = '"', '0', 'x'
	hex.Encode(out[3:], *c)
	out[len(*c)-1] = '"'
	return out, nil
}

func (c *VariableLenCode) UnmarshalJSON(data []byte) error {
	if !bytes.HasPrefix(data, []byte(`"`)) || !bytes.HasSuffix(data, []byte(`"`)) {
		return fmt.Errorf("code must be in a string")
	}
	data = bytes.Trim(data, "\"")
	data = bytes.TrimPrefix(data, []byte("0x"))
	decoded := make([]byte, hex.DecodedLen(len(data)))
	_, err := hex.Decode(decoded, data)
	if err != nil {
		return err
	}
	*c = decoded
	return nil
}
