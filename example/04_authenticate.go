package main

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"strings"
	"time"

	"github.com/ockam-network/did"
	"github.com/ockam-network/ockam"
	"github.com/ockam-network/ockam/claim"
	"github.com/ockam-network/ockam/entity"
	"github.com/ockam-network/ockam/key/ed25519"
	"github.com/ockam-network/ockam/key/rsa"
	"github.com/ockam-network/ockam/node"
	"github.com/ockam-network/ockam/node/remote/http"
	"github.com/piprate/json-gold/ld"
)

func main() {
	name := flag.String("name", "", "name of the service that will be started.")
	port := flag.Int("port", 6000, "the port this service will listen on.")
	flag.Parse()

	ockamChain := connect()
	thisService := setup(ockamChain, *name, *port)

	target := flag.Arg(0)
	if target == "" {
		listen(ockamChain, thisService, *port)
	} else {
		auth(ockamChain, thisService, target)
	}
}

func connect() ockam.Chain {
	ockamNode, err := node.New(node.PeerDiscoverer(http.Discoverer("test.ockam.network", 26657)))
	exitOnError(err)

	err = ockamNode.Sync()
	exitOnError(err)

	ockamChain := ockamNode.Chain()
	fmt.Printf(green("=> Connected to Ockam: %s\n"), ockamChain.ID())
	return ockamChain
}

func setup(c ockam.Chain, name string, port int) ockam.Entity {
	fmt.Printf(green("=> Setting up: %s\n"), name)
	signer := setupSigner(name)
	e, err := entity.New(entity.Attributes{
		"name":            name,
		"serviceEndpoint": fmt.Sprintf(":%d", port),
	}, entity.Signer(signer))
	fmt.Printf(green("  => DID: %s\n"), e.ID())
	exitOnError(err)
	ensureRegistered(e, c)
	return e
}

func ensureRegistered(e ockam.Entity, c ockam.Chain) {
	bytes, _, err := c.FetchEntity(e.ID().String())
	if err != nil {
		if err.Error() == "does not exist" {

			fmt.Printf(green("  => Registering: %s\n"), e.ID())
			_, err = c.Register(e)
			exitOnError(err)
			time.Sleep(5 * time.Second)
			ensureRegistered(e, c)

		} else {
			exitOnError(err)
		}
	} else {
		fmt.Printf(green("  => Registered DID Document:\n"))
		err = printJSON(bytes)
		exitOnError(err)
	}
}

func setupSigner(name string) *rsa.RSA {
	var signer *rsa.RSA
	var content []byte

	var publicKey []byte
	var privateKey []byte

	privateKeyPath := name
	publicKeyPath := name + ".pub"

	_, err := os.Stat(privateKeyPath)
	if err == nil {
		fmt.Printf(green("  => Private key found: %s\n"), privateKeyPath)

		content, err = ioutil.ReadFile(privateKeyPath)
		exitOnError(err)

		privateKey, err = hex.DecodeString(string(content))
		exitOnError(err)

		content, err = ioutil.ReadFile(publicKeyPath)
		exitOnError(err)

		publicKey, err = hex.DecodeString(string(content))
		exitOnError(err)

		signer, err = rsa.New(rsa.PrivateKey(privateKey), rsa.PublicKey(publicKey))
		exitOnError(err)

	} else if os.IsNotExist(err) {
		fmt.Printf(green("  => Private key not found: %s\n  => Generating ...\n"), privateKeyPath)

		signer, err = rsa.New()
		exitOnError(err)

		err = ioutil.WriteFile(privateKeyPath, []byte(hex.EncodeToString(signer.PrivateKey())), 0644)
		exitOnError(err)
		fmt.Printf(green("  => Generated private key: %s\n"), privateKeyPath)

		err = ioutil.WriteFile(publicKeyPath, []byte(signer.PublicKey().Value()), 0644)
		exitOnError(err)
		fmt.Printf(green("  => Generated public key: %s\n"), publicKeyPath)

	} else {
		exitOnError(err)
	}

	return signer
}

func listen(ockamChain ockam.Chain, thisService ockam.Entity, port int) {
	// 		fmt.Fprintf(w, "=> Connected to Ockam: %s\n", ockamChain.ID())
	// 		fmt.Fprintf(w, "=> Service DID: %s\n", thisService.ID())

	ln, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
	exitOnError(err)
	fmt.Printf(green("=> Listening on port: %d\n"), port)
	fmt.Printf(green("=> Waiting for auth challenge to: %s\n"), thisService.ID())

	conn, err := ln.Accept()
	exitOnError(err)

	// run loop forever (or until ctrl-c)
	for {
		// will listen for message to process ending in newline (\n)
		message, _ := bufio.NewReader(conn).ReadString('\n')
		message = strings.TrimSuffix(message, "\n")

		fmt.Printf(green("  => [3] Auth Challenge:\n"))
		printJSON([]byte(message))

		challenge := claimFromJSON(message)
		data := challenge.Data()
		challengeString := data["challenge"]

		fmt.Printf(green("    => [3] Issuer: %s\n"), challenge.Issuer().ID())
		bytes, _, err := ockamChain.FetchEntity(challenge.Issuer().ID().String())
		exitOnError(err)
		fmt.Printf(green("  => [4] Registered DID Document:\n"))
		err = printJSON(bytes)
		exitOnError(err)

		// TODO verify sig

		fmt.Printf(green("  => [5] Prepare Auth Challenge Response:\n"))
		challengeResponse, err := claim.New(
			claim.Data{
				"challenge":  challengeString,
				"challenge1": "5678", // todo: random
			},
			claim.Issuer(thisService),
			claim.Subject(thisService),
		)
		exitOnError(err)

		signer := thisService.Signers()[0]
		signer.Sign(challengeResponse)

		j, err := challengeResponse.MarshalJSON()
		exitOnError(err)
		newline := []byte("\n")
		j = append(j, newline...)
		fmt.Fprintf(conn, string(j))

		fmt.Printf(green("  => [5] Auth Challenge Response:\n"))
		printJSON(j)

		fmt.Printf(green("  => [5] Waiting for Response's response:\n"))
		message, _ = bufio.NewReader(conn).ReadString('\n')
		message = strings.TrimSuffix(message, "\n")

		fmt.Printf(green("  => [6] Got Response's response:\n"))
		printJSON([]byte(message))

		challenge1ResponseR := claimFromJSON(message)
		data = challenge1ResponseR.Data()
		challenge1String := data["challenge1"]
		if challenge1String == "5678" {
			fmt.Printf(green("  => [7] Authenticated: %s\n"), challenge.Issuer().ID())
		} else {
			fmt.Printf(green("  => [7] Not Authenticated: %s\n"), challenge.Issuer().ID())
		}

	}
}

func auth(ockamChain ockam.Chain, thisService ockam.Entity, target string) {
	fmt.Printf(green("=> [1] Authenticating with: %s\n"), target)

	bytes, otherService, err := ockamChain.FetchEntity(target)
	exitOnError(err)

	fmt.Printf(green("  => [2] Registered DID Document:\n"))
	err = printJSON(bytes)
	exitOnError(err)

	m := otherService.Attributes()

	conn, err := net.Dial("tcp", m["serviceEndpoint"].(string))
	exitOnError(err)

	challenge, err := claim.New(
		claim.Data{
			"challenge": "1234", // todo: random
		},
		claim.Issuer(thisService),
		claim.Subject(thisService),
	)
	exitOnError(err)

	signer := thisService.Signers()[0]
	signer.Sign(challenge)

	j, err := challenge.MarshalJSON()
	exitOnError(err)
	newline := []byte("\n")
	j = append(j, newline...)

	fmt.Printf(green("  => [3] Sending Challenge:\n"))
	err = printJSON(j)
	exitOnError(err)
	fmt.Fprintf(conn, string(j))

	fmt.Printf(green("  => [3] Waiting for challenge response:\n"))
	message, _ := bufio.NewReader(conn).ReadString('\n')

	fmt.Printf(green("  => [5] Got challenge response:\n"))
	printJSON([]byte(message))

	challengeResponse := claimFromJSON(message)
	data := challengeResponse.Data()
	challengeString := data["challenge"]
	if challengeString == "1234" {
		fmt.Printf(green("  => [6] Authenticated: %s\n"), otherService.ID())
	} else {
		fmt.Printf(grey("  => [6] Not Authenticated: %s\n"), otherService.ID())
	}

	challenge1String := data["challenge1"]

	challenge1Response, err := claim.New(
		claim.Data{
			"challenge1": challenge1String,
		},
		claim.Issuer(thisService),
		claim.Subject(thisService),
	)
	exitOnError(err)

	signer.Sign(challenge1Response)

	j, err = challenge1Response.MarshalJSON()
	exitOnError(err)
	newline = []byte("\n")
	j = append(j, newline...)
	fmt.Printf(green("  => [6] Sent challenge response: \n"))
	printJSON(j)
	fmt.Fprintf(conn, string(j))

	// canonicalized := canonicalize(challenge)
	// newline := []byte("\n")
	// canonicalized = append(canonicalized, newline...)
	// fmt.Fprintf(conn, string(canonicalized))

	for {
		// read in input from stdin
		reader := bufio.NewReader(os.Stdin)
		// fmt.Print("Text to send: ")
		text, _ := reader.ReadString('\n')
		// send to socket
		fmt.Fprintf(conn, text+"\n")
		// listen for reply
		message, _ := bufio.NewReader(conn).ReadString('\n')
		fmt.Print("Message from server: " + message)
	}
}

func canonicalize(c ockam.Claim) []byte {
	claimJSON, err := c.MarshalJSON()
	exitOnError(err)

	var claimMap map[string]interface{}
	err = json.Unmarshal(claimJSON, &claimMap)
	exitOnError(err)

	proc := ld.NewJsonLdProcessor()
	options := ld.NewJsonLdOptions("")
	options.Format = "application/nquads"
	options.Algorithm = "URDNA2015"

	canonicalized, err := proc.Normalize(claimMap, options)
	exitOnError(err)

	b := []byte(canonicalized.(string))

	return b
}

func claimFromJSON(j string) ockam.Claim {
	//unmarshal into map so we can access fields to create claim
	var m map[string]interface{}
	err := json.Unmarshal([]byte(j), &m)
	exitOnError(err)

	//get the type
	typeArray := m["type"].([]interface{})
	t := typeArray[0].(string)

	//get the subject from the claim field
	claimMap := m["claim"].(map[string]interface{})

	var empty map[string]interface{}
	subject, err := did.Parse(claimMap["id"].(string))
	exitOnError(err)

	subjectEntity, err := entity.New(empty, entity.ID(subject))
	exitOnError(err)

	//get issuer from issuer field
	issuer, err := did.Parse(m["issuer"].(string))
	exitOnError(err)
	issuerEntity, err := entity.New(empty, entity.ID(issuer))
	exitOnError(err)

	cl, err := claim.New(
		claimMap,
		claim.Issuer(issuerEntity),
		claim.Subject(subjectEntity),
		claim.Type(t),
		claim.ID(m["id"].(string)),
		claim.Issued(m["issued"].(string)),
	)
	exitOnError(err)

	signatures := m["signatures"].([]interface{})
	for _, s := range signatures {
		sig := s.(map[string]interface{})
		if sig["type"].(string) == "Ed25519Signature2018" { //Todo: add support for other sig types, consider switch statement
			signature := ed25519.AssembleSignature(
				sig["type"].(string),
				sig["creator"].(string),
				sig["created"].(string),
				sig["domain"].(string),
				sig["nonce"].(string),
				[]byte(sig["signatureValue"].(string)))
			cl.AddSignature(signature)
		}

		if sig["type"].(string) == "RSASignature2018" {
			signature := rsa.AssembleSignature(
				sig["type"].(string),
				sig["creator"].(string),
				sig["created"].(string),
				sig["domain"].(string),
				sig["nonce"].(string),
				[]byte(sig["signatureValue"].(string)))
			cl.AddSignature(signature)
		}
	}

	return cl
}

func printJSON(j []byte) error {
	var prettyJSON bytes.Buffer
	err := json.Indent(&prettyJSON, j, "      ", "  ")
	if err != nil {
		return err
	}
	fmt.Printf("       %s\n", string(prettyJSON.Bytes()))
	return nil
}

func exitOnError(err error) {
	if err != nil {
		fmt.Fprintf(os.Stderr, "%+v\n", err)
		os.Exit(1)
	}
}

func color(s string, c int) string {
	return fmt.Sprintf("\x1b[0;%dm%s\x1b[0m", c, s)
}

func green(s string) string {
	return color(s, 32)
}

func grey(s string) string {
	return color(s, 30)
}

// err = aSigner.Sign(challenge)
// exitOnError(err)
//
// canonicalized := canonicalize(challenge)
// fmt.Printf("%+v\n", canonicalized)
//
// der, err := hex.DecodeString(b.PublicKeys()[0].Value())
// exitOnError(err)
//
// rsaKey, err := x509.ParsePKCS1PublicKey(der)
// exitOnError(err)
//
// aesKey := make([]byte, 16)
// _, err = rand.Read(aesKey)
// exitOnError(err)
//
// aesCipher, err := aes.NewCipher(aesKey)
// exitOnError(err)
//
// ciphertext, err := r.EncryptOAEP(sha256.New(), rand.Reader, rsaKey, canonicalized, []byte("label"))
// exitOnError(err)
//
// // Since encryption is a randomized function, ciphertext will be
// // different each time.
// fmt.Printf("Ciphertext: %x\n", ciphertext)
