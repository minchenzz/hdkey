package hdkey

import (
	"strconv"
	"strings"

	"github.com/btcsuite/btcd/btcec"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcutil/hdkeychain"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/tyler-smith/go-bip39"
	"github.com/tyler-smith/go-bip39/wordlists"
)

func NewMnemonic(isChinese bool) (mnemonic string) {
	entropy, _ := bip39.NewEntropy(128)
	if isChinese {
		bip39.SetWordList(wordlists.ChineseSimplified)
	} else {
		bip39.SetWordList(wordlists.English)
	}
	mnemonic, _ = bip39.NewMnemonic(entropy)
	return
}

func MnemonicToRootXpri(mnemonic string, password string) (xpri string, err error) {
	seed, err := bip39.NewSeedWithErrorChecking(mnemonic, password)
	if err != nil {
		return
	}

	root, err := hdkeychain.NewMaster(seed, &chaincfg.MainNetParams)
	if err != nil {
		return
	}
	xpri = root.String()
	return
}

func GenerateAddressByRootKey(rootXpri, path string) (address string, err error) {
	pathList := parsePath(path)
	var next *hdkeychain.ExtendedKey
	var xkey = rootXpri
	for _, floor := range pathList {
		idx := floor[0]
		isHardened := floor[1] == 1
		next, err = nextFloor(xkey, isHardened, uint32(idx))
		if err != nil {
			return
		}
		xkey = next.String()
	}
	pri, err := next.ECPrivKey()
	if err != nil {
		return
	}

	return crypto.PubkeyToAddress(pri.PublicKey).Hex(), nil
}

func GeneratePrivateKeyByPath(rootXpri, path string) (pri *btcec.PrivateKey, err error) {
	pathList := parsePath(path)
	var next *hdkeychain.ExtendedKey
	var xkey = rootXpri
	for _, floor := range pathList {
		idx := floor[0]
		isHardened := floor[1] == 1
		next, err = nextFloor(xkey, isHardened, uint32(idx))
		if err != nil {
			return
		}
		xkey = next.String()
	}
	return next.ECPrivKey()
}

// 返回一个二维数组 参数1 对应每一层偏移 参数2  1代表hardened 0普通
func parsePath(path string) [][]int {
	l := strings.Split(path, "/")
	var resList [][]int
	// m开头或者/开头 去掉第一个
	if l[0] == "m" || l[0] == "" {
		l = l[1:]
	}
	// /结尾 去掉最后一个
	if l[len(l)-1] == "" {
		l = l[:len(l)-1]
	}
	for _, s := range l {
		if strings.HasSuffix(s, "'") {
			idx, _ := strconv.Atoi(s[:len(s)-1])
			resList = append(resList, []int{idx, 1})
		} else {
			idx, _ := strconv.Atoi(s)
			resList = append(resList, []int{idx, 0})
		}
	}
	return resList
}

func nextFloor(key string, hardened bool, idx uint32) (*hdkeychain.ExtendedKey, error) {
	key1, err := hdkeychain.NewKeyFromString(key)
	if err != nil {
		return nil, err
	}
	if hardened {
		return key1.Child(hdkeychain.HardenedKeyStart + idx)
	} else {
		return key1.Child(idx)
	}
}
