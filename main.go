package main

import (
	"fmt"
	"github.com/ethereum/go-ethereum/accounts/keystore"
	"os"
	"runtime"
	"sync"
)

/**
 *
 * PotentialPassword length must equal to real password length.
 *
 * 1. Update potentialPassword in main function. The length is important.
 * 2. Update jsonKeyStore
 * 3. Run this program use `go run main.go`
 * 4. If it's failed. Improve getPotentialAlternatives and try again.
 */

// correct password is "ThisIsASecret";
var jsonKeyStore = []byte(`
{
  "version": 3,
  "id": "f82f9a71-8ad9-43b4-857f-c67ab7631df2",
  "address": "82815f551f7ffa8a9ccb4d2e20dffc745b25e59d",
  "crypto": {
    "ciphertext": "a7572a7b76642af51c45efb1c818700c81c8d359820ce6b05301280c1bc9dced",
    "cipherparams": {
      "iv": "047dd8f96b968d53bcc2101f8d0b1221"
    },
    "cipher": "aes-128-ctr",
    "kdf": "scrypt",
    "kdfparams": {
      "dklen": 32,
      "salt": "30a39fc550d35d11eacde83263218829536fb217b8ca7e37f6061e24277a8eaf",
      "n": 131072,
      "r": 8,
      "p": 1
    },
    "mac": "b43a2f47887f347ad43599c04f3ff5d40e7742ae274b8e39974488f3d35c71ca"
  }
}`)

var chars = []byte("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")

// return the potential wrong options of a char typing by mistaken
func getPotentialAlternatives(char byte) []byte {

	if char >= 'A' && char <= 'Z' {
		res := []byte{}
		for _, c := range getPotentialAlternatives(char + ('a' - byte('A'))) {
			res = append(res, c-('a'-byte('A')))
		}
		return res
	}

	if char >= '0' && char <= '9' {
		if char == '0' {
			return []byte{'1'}
		}

		if char == '9' {
			return []byte{'8'}
		}

		return []byte{char + 1, char - 1}
	}

	switch char {
	case 'a':
		return []byte{'q', 's'}
	case 'b':
		return []byte{'v', 'g', 'n'}
	case 'c':
		return []byte{'x', 'v'}
	case 'd':
		return []byte{'s', 'f'}
	case 'e':
		return []byte{'w', 'r'}
	case 'f':
		return []byte{'g', 'd'}
	case 'g':
		return []byte{'h', 'f', 'v'}
	case 'h':
		return []byte{'g', 'j'}
	case 'i':
		return []byte{'u', 'o'}
	case 'j':
		return []byte{'h', 'k'}
	case 'k':
		return []byte{'j', 'l'}
	case 'l':
		return []byte{'k', ';', '.', ','}
	case 'm':
		return []byte{'n', ','}
	case 'n':
		return []byte{'m', 'b'}
	case 'o':
		return []byte{'i', 'p'}
	case 'p':
		return []byte{'o', '['}
	case 'q':
		return []byte{'w', 'a'}
	case 'r':
		return []byte{'e', 't'}
	case 's':
		return []byte{'h', 'f'}
	case 't':
		return []byte{'r', 'y'}
	case 'u':
		return []byte{'y', 'i'}
	case 'v':
		return []byte{'c', 'b', 'f'}
	case 'w':
		return []byte{'q', 'e'}
	case 'x':
		return []byte{'z', 'c'}
	case 'y':
		return []byte{'h', 'u', 't'}
	case 'z':
		return []byte{'a', 'x'}
	case ';':
		return []byte{'l'}
	case '[':
		return []byte{'p'}
	}

	return chars
}

func tryPassword(password string) bool {
	_, err := keystore.DecryptKey(jsonKeyStore, password)
	fmt.Printf("%s\n", password)
	if err != nil {
		return false
	}

	for i := 0; i < 10; i++ {
		fmt.Printf("password is %s !!!!!!!!!!!!!!\n", password)
	}

	return true
}

func try(potentialPassword []byte) {

	if tryPassword(string(potentialPassword)) {
		return
	}

	// concurrent channel
	ch := make(chan string, runtime.NumCPU())

	// consumers
	wg := sync.WaitGroup{}
	for i := 0; i < runtime.NumCPU(); i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for p := range ch {
				if tryPassword(p) {
					os.Exit(0)
				}
			}
		}()
	}

	// producer
	count := 0
	for i := 0; i < len(potentialPassword)-2+1; i++ {
		oldJ := potentialPassword[i]
		oldK := potentialPassword[i+1]

		jAlternatives := append(getPotentialAlternatives(oldJ), oldJ)
		kAlternatives := append(getPotentialAlternatives(oldK), oldK)

		for j := 0; j < len(jAlternatives); j++ {
			potentialPassword[i] = jAlternatives[j]

			for k := 0; k < len(kAlternatives); k++ {
				potentialPassword[i+1] = kAlternatives[k]

				ch <- string(potentialPassword)

				count++
				if count%1000 == 0 {
					fmt.Printf("count %d\n", count)
				}
			}
		}

		potentialPassword[i] = oldJ
		potentialPassword[i+1] = oldK
	}

	close(ch)

	wg.Wait()

	fmt.Println("Failed !!!!!!!!!")
}

func main() {
	// try([]byte("ThisIsASrvret"))
	//                     ^^

	// try([]byte("ThisOsASecret"))
	//                 ^

	// try([]byte("ThisIsASecrer"))
	//                         ^

	try([]byte("RhisIsASecret"))
	//          ^
}
