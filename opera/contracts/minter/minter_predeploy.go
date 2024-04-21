package nativeminter

import (
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
)

// GetContractBin is NetworkInitializer contract genesis implementation bin code
// Has to be compiled with flag bin-runtime
// Built from opera-sfc 424031c81a77196f4e9d60c7d876032dd47208ce, solc 0.5.17+commit.d19bba13.Emscripten.clang, optimize-runs 10000
func GetContractBin() []byte {
	return hexutil.MustDecode("0x608060405234801561001057600080fd5b50600436106100d45760003560e01c8063983b2d5611610081578063f2fde38b1161005b578063f2fde38b14610224578063f46eccc414610257578063f6d7d88a1461028a576100d4565b8063983b2d56146101a4578063a4cb7a67146101d7578063c0c53b8b146101df576100d4565b80638992229f116100b25780638992229f1461014f5780638da5cb5b146101805780638f32d59b14610188576100d4565b806316c5cf9f146100d95780633092afd514610114578063715018a614610147575b600080fd5b610112600480360360408110156100ef57600080fd5b5073ffffffffffffffffffffffffffffffffffffffff81351690602001356102c3565b005b6101126004803603602081101561012a57600080fd5b503573ffffffffffffffffffffffffffffffffffffffff16610488565b610112610547565b610157610629565b6040805173ffffffffffffffffffffffffffffffffffffffff9092168252519081900360200190f35b610157610645565b610190610661565b604080519115158252519081900360200190f35b610112600480360360208110156101ba57600080fd5b503573ffffffffffffffffffffffffffffffffffffffff1661067f565b610157610741565b610112600480360360608110156101f557600080fd5b5073ffffffffffffffffffffffffffffffffffffffff813581169160208101358216916040909101351661075d565b6101126004803603602081101561023a57600080fd5b503573ffffffffffffffffffffffffffffffffffffffff166108d2565b6101906004803603602081101561026d57600080fd5b503573ffffffffffffffffffffffffffffffffffffffff16610951565b610112600480360360408110156102a057600080fd5b5073ffffffffffffffffffffffffffffffffffffffff8135169060200135610966565b3360009081526066602052604090205460ff1661034157604080517f08c379a000000000000000000000000000000000000000000000000000000000815260206004820152601660248201527f63616c6c6572206973206e6f742061206d696e74657200000000000000000000604482015290519081900360640190fd5b60685473ffffffffffffffffffffffffffffffffffffffff9081169063e30443bc908490610378908216318563ffffffff610b0f16565b6040518363ffffffff1660e01b8152600401808373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200182815260200192505050600060405180830381600087803b1580156103e157600080fd5b505af11580156103f5573d6000803e3d6000fd5b5050606754604080517f7ad7978700000000000000000000000000000000000000000000000000000000815260048101869052905173ffffffffffffffffffffffffffffffffffffffff9092169350637ad79787925060248082019260009290919082900301818387803b15801561046c57600080fd5b505af1158015610480573d6000803e3d6000fd5b505050505050565b610490610661565b6104fb57604080517f08c379a000000000000000000000000000000000000000000000000000000000815260206004820181905260248201527f4f776e61626c653a2063616c6c6572206973206e6f7420746865206f776e6572604482015290519081900360640190fd5b73ffffffffffffffffffffffffffffffffffffffff16600090815260666020526040902080547fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff00169055565b61054f610661565b6105ba57604080517f08c379a000000000000000000000000000000000000000000000000000000000815260206004820181905260248201527f4f776e61626c653a2063616c6c6572206973206e6f7420746865206f776e6572604482015290519081900360640190fd5b60335460405160009173ffffffffffffffffffffffffffffffffffffffff16907f8be0079c531659141344cd1fd0a4f28419497f9722a3daafe3b4186f6b6457e0908390a3603380547fffffffffffffffffffffffff0000000000000000000000000000000000000000169055565b60675473ffffffffffffffffffffffffffffffffffffffff1681565b60335473ffffffffffffffffffffffffffffffffffffffff1690565b60335473ffffffffffffffffffffffffffffffffffffffff16331490565b610687610661565b6106f257604080517f08c379a000000000000000000000000000000000000000000000000000000000815260206004820181905260248201527f4f776e61626c653a2063616c6c6572206973206e6f7420746865206f776e6572604482015290519081900360640190fd5b73ffffffffffffffffffffffffffffffffffffffff16600090815260666020526040902080547fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff00166001179055565b60685473ffffffffffffffffffffffffffffffffffffffff1681565b600054610100900460ff16806107765750610776610b58565b80610784575060005460ff16155b6107d9576040517f08c379a000000000000000000000000000000000000000000000000000000000815260040180806020018281038252602e815260200180610f2d602e913960400191505060405180910390fd5b600054610100900460ff1615801561083f57600080547fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff007fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff00ff909116610100171660011790555b61084882610b5e565b6067805473ffffffffffffffffffffffffffffffffffffffff8087167fffffffffffffffffffffffff000000000000000000000000000000000000000092831617909255606880549286169290911691909117905580156108cc57600080547fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff00ff1690555b50505050565b6108da610661565b61094557604080517f08c379a000000000000000000000000000000000000000000000000000000000815260206004820181905260248201527f4f776e61626c653a2063616c6c6572206973206e6f7420746865206f776e6572604482015290519081900360640190fd5b61094e81610ce7565b50565b60666020526000908152604090205460ff1681565b3360009081526066602052604090205460ff166109e457604080517f08c379a000000000000000000000000000000000000000000000000000000000815260206004820152601660248201527f63616c6c6572206973206e6f742061206d696e74657200000000000000000000604482015290519081900360640190fd5b60685473ffffffffffffffffffffffffffffffffffffffff9081169063e30443bc908490610a1b908216318563ffffffff610de116565b6040518363ffffffff1660e01b8152600401808373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200182815260200192505050600060405180830381600087803b158015610a8457600080fd5b505af1158015610a98573d6000803e3d6000fd5b5050606754604080517f0553fd5b00000000000000000000000000000000000000000000000000000000815260048101869052905173ffffffffffffffffffffffffffffffffffffffff9092169350630553fd5b925060248082019260009290919082900301818387803b15801561046c57600080fd5b6000610b5183836040518060400160405280601e81526020017f536166654d6174683a207375627472616374696f6e206f766572666c6f770000815250610e55565b9392505050565b303b1590565b600054610100900460ff1680610b775750610b77610b58565b80610b85575060005460ff16155b610bda576040517f08c379a000000000000000000000000000000000000000000000000000000000815260040180806020018281038252602e815260200180610f2d602e913960400191505060405180910390fd5b600054610100900460ff16158015610c4057600080547fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff007fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff00ff909116610100171660011790555b603380547fffffffffffffffffffffffff00000000000000000000000000000000000000001673ffffffffffffffffffffffffffffffffffffffff84811691909117918290556040519116906000907f8be0079c531659141344cd1fd0a4f28419497f9722a3daafe3b4186f6b6457e0908290a38015610ce357600080547fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff00ff1690555b5050565b73ffffffffffffffffffffffffffffffffffffffff8116610d53576040517f08c379a0000000000000000000000000000000000000000000000000000000008152600401808060200182810382526026815260200180610f076026913960400191505060405180910390fd5b60335460405173ffffffffffffffffffffffffffffffffffffffff8084169216907f8be0079c531659141344cd1fd0a4f28419497f9722a3daafe3b4186f6b6457e090600090a3603380547fffffffffffffffffffffffff00000000000000000000000000000000000000001673ffffffffffffffffffffffffffffffffffffffff92909216919091179055565b600082820183811015610b5157604080517f08c379a000000000000000000000000000000000000000000000000000000000815260206004820152601b60248201527f536166654d6174683a206164646974696f6e206f766572666c6f770000000000604482015290519081900360640190fd5b60008184841115610efe576040517f08c379a00000000000000000000000000000000000000000000000000000000081526004018080602001828103825283818151815260200191508051906020019080838360005b83811015610ec3578181015183820152602001610eab565b50505050905090810190601f168015610ef05780820380516001836020036101000a031916815260200191505b509250505060405180910390fd5b50505090039056fe4f776e61626c653a206e6577206f776e657220697320746865207a65726f2061646472657373436f6e747261637420696e7374616e63652068617320616c7265616479206265656e20696e697469616c697a6564a265627a7a72315820d2268a0dba6eafbcb135ad206e34fa997f052decf4aa5a7a5232db310502860064736f6c63430005110032")
}

// ContractAddress is the NetworkInitializer contract address
var ContractAddress = common.HexToAddress("0x6d696e7400000000000000000000000000000000")
