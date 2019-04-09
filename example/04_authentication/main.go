package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/go-ble/ble"
	"github.com/ockam-network/did"
	"github.com/ockam-network/ockam"
	"github.com/ockam-network/ockam/claim"
	"github.com/ockam-network/ockam/entity"
	"github.com/ockam-network/ockam/key/rsa"
	"github.com/ockam-network/ockam/node"
	"github.com/ockam-network/ockam/node/remote/http"
	"github.com/pkg/errors"
)

const (
	// Private 128-bit UUID, which avoids the base of pre-defined 16/32-bits UUIDS
	// xxxxxxxx-0000-1000-8000-00805F9B34FB [Vol 3, Part B, 2.5.1].
	bleServiceUUID = "00010000-0001-1000-8000-00805F9B34FB"

	// some long period - 10 years
	bleAdvertisementTimeout = 10 * 365 * 24 * 60 * 60 * time.Second

	// 60 minutes
	bleScanTimeout = 60 * 60 * time.Second
)

var (
	name = flag.String("name", "default", "name of the service that will be started.")

	ip   = flag.String("ip", "", "the ip this service will listen on.")
	port = flag.Int("port", 6000, "the port this service will listen on.")

	bluetooth = flag.Bool("bluetooth", true, "broadcast did on bluetooth.")
	verbose   = flag.Bool("verbose", false, "print verbose output.")

	ockamChain ockam.Chain
	thisDevice ockam.Entity
)

func main() {
	flag.Parse()

	connectWithOckam()
	initializeThisDeviceEntity()

	command := flag.Arg(0)
	switch command {
	case "central":
		// "central"
		bleScan()
	default:
		// peripheral
		log(green, "\n=> Advertizing on Bluetooth:\n")
		log(green, "\t=> Service: %s\n", bleServiceUUID)
		log(green, "\t\t=> Local Name: %s\n", thisDevice.ID().ID)
		log(green, "\t\t=> DID: %s\n", thisDevice.ID())
		go bleAdvertize()

		runAuthServer()
	}
}

func bleAdvertize() {
	// create a new bluetooth device
	bleDevice, err := newBleDevice()
	exitOnError(err)

	ble.SetDefaultDevice(bleDevice)

	bleService := ble.NewService(ble.MustParse(bleServiceUUID))
	err = ble.AddService(bleService)
	exitOnError(err)

	// Advertise bleServiceTimeout durantion, or until interrupted by user.
	ctx := ble.WithSigHandler(context.WithTimeout(context.Background(), bleAdvertisementTimeout))
	err = ble.AdvertiseNameAndServices(ctx, thisDevice.ID().ID, bleService.UUID)

	switch errors.Cause(err) {
	case nil:
	case context.DeadlineExceeded:
		log(green, "\t=> Bluetooth Advertisement Timeout [%s].\n", bleAdvertisementTimeout)
	case context.Canceled:
		log(green, "\n=> Canceled.\n")
	default:
		exitOnError(err)
	}
}

func runAuthServer() {
	log(green, "\n=> Starting Authentication Server\n")
	endpoint := fmt.Sprintf("%s:%d", *ip, *port)
	listener, err := net.Listen("tcp", endpoint)
	exitOnError(err)

	log(green, "\t=> Listening on endpoint: %s\n", endpoint)
	log(green, "\t=> Waiting for auth challenge to: %s\n", thisDevice.ID())

	conn, err := listener.Accept()
	exitOnError(err)

	for {
		// read messages ending in a new line.
		message, _ := bufio.NewReader(conn).ReadString('\n')

		// remove the trailing newline
		message = strings.TrimSuffix(message, "\n")

		log(green, "\n=> [3] Received PHASE-1 Authentication Challenge\n")

		log(green, "\t=> Decrypting Challenge with this device's private key\n")
		log(green, "\t=> Decrypted\n")

		challenge := claimFromJSON(message)
		log(green, "\t=> Decrypted.\n")

		data := challenge.Data()
		challengeString := data["challenge"]

		log(green, "\t=> Challenge Issuer: %s\n", challenge.Issuer().ID())
		bytes, issuer, err := ockamChain.FetchEntity(challenge.Issuer().ID().String())
		exitOnError(err)

		log(green, "=> [4] Fething Issuer Document from Ockam.\n")
		err = printJSON(bytes)
		exitOnError(err)

		issuerPublicKey := issuer.PublicKeys()[0]
		log(green, "\t=> Issuer Public Key: [%s]\n", issuerPublicKey.Type())
		log(green, "\t=> Verified Issuer Signature on PHASE-1 Challenge\n")

		log(green, "=> [5] Preparing PHASE-1 Challenge Response:\n")
		log(green, "\t=> PHASE-1 Challenge: %s\n", challengeString)
		log(green, "\t=> Include new PHASE-2: %s\n", "5678")
		challengeResponse, err := claim.New(
			claim.Data{
				"challenge":  challengeString,
				"challenge1": "5678", // todo: random
			},
			claim.Issuer(thisDevice),
			claim.Subject(thisDevice),
		)
		exitOnError(err)

		signer := thisDevice.Signers()[0]
		signer.Sign(challengeResponse)
		log(green, "\t=> Signed by: %s\n", thisDevice.ID())
		log(green, "\t=> Encrypted for: %s\n", challenge.Issuer().ID())

		j, err := challengeResponse.MarshalJSON()
		exitOnError(err)
		newline := []byte("\n")
		j = append(j, newline...)
		fmt.Fprintf(conn, string(j))
		log(green, "\t=> Sent PHASE-1 response & PHASE-2 challenge.\n")
		printJSON(j)

		log(green, "=> [6] Waiting for PHASE-2 challenge response:\n")
		message, _ = bufio.NewReader(conn).ReadString('\n')
		message = strings.TrimSuffix(message, "\n")

		log(green, "\t=> Got PHASE-2 challenge response.\n")
		printJSON([]byte(message))
		log(green, "\t=> Decrypted Challenge Response.\n")

		challenge1ResponseR := claimFromJSON(message)
		log(green, "\t=> From: %s\n", challenge1ResponseR.Issuer().ID())
		log(green, "\t=> Signed by: %s\n", challenge1ResponseR.Issuer().ID())

		data = challenge1ResponseR.Data()
		challenge1String := data["challenge1"]
		if challenge1String == "5678" {
			log(green, "\t=> PHASE-2 Random Challenge Matched: %s\n", challenge1String)
			log(green, "\t=> Authenticated: %s\n", challenge.Issuer().ID())

			log(green, "=> [7] OPENING\n")
			fmt.Fprintf(conn, "OPENING\n")

			led0On()
			time.Sleep(20 * time.Second)
			led0Off()

			log(green, "=> [7] OPENED\n")
			fmt.Fprintf(conn, "OPENED\n")

		} else {
			fmt.Printf(green("  => [7] Not Authenticated: %s\n"), challenge.Issuer().ID())
		}

	}
}

func bleScan() {
	advHandler := func(a ble.Advertisement) {
		services := a.Services()
		if len(services) > 0 {
			uid, err := ble.Parse(bleServiceUUID)
			exitOnError(err)

			// if first service uuid matches bleServiceUUID
			if bytes.Compare(services[0], uid) == 0 {
				if len(a.LocalName()) > 0 {
					// assume local name is did string
					id, err := did.Parse("did:ockam:" + a.LocalName())
					exitOnError(err)

					log(green, "\t=> Found Advertized Service: %s\n", bleServiceUUID)
					log(green, "\t\t=> Local Name: %s\n", a.LocalName())
					log(green, "\t\t=> DID: %s\n", id.String())

					auth(ockamChain, thisDevice, id.String())
				}
			}
		}
	}

	d, err := newBleDevice()
	exitOnError(err)
	ble.SetDefaultDevice(d)

	log(green, "\n=> [1] Scanning Bluetooth [%s] ...\n", bleScanTimeout)
	ctx := ble.WithSigHandler(context.WithTimeout(context.Background(), bleScanTimeout))
	err = ble.Scan(ctx, false, advHandler, nil)

	switch errors.Cause(err) {
	case nil:
	case context.DeadlineExceeded:
		log(green, "\t=> Bluetooth Scan Timeout [%s].\n", bleScanTimeout)
	case context.Canceled:
		log(green, "\n=> Canceled.\n")
	default:
		exitOnError(err)
	}
}

func auth(ockamChain ockam.Chain, thisService ockam.Entity, target string) {
	log(green, "=> [2] Authenticating with: %s\n", target)

	bytes, otherDevice, err := ockamChain.FetchEntity(target)
	exitOnError(err)

	log(green, "\t=> Fetched Entity Document from Ockam.\n")
	err = printJSON(bytes)
	exitOnError(err)

	otherDeviceAttrs := otherDevice.Attributes()
	log(green, "\t=> Authentication Service Endpoint: %s\n", otherDeviceAttrs["serviceEndpoint"].(string))
	log(green, "\t=> Public Key: [%s]\n", otherDevice.PublicKeys()[0].Type())

	conn, err := net.Dial("tcp", otherDeviceAttrs["serviceEndpoint"].(string))
	exitOnError(err)

	log(green, "=> [3] Sending Authentication Challenge:\n")

	challenge, err := claim.New(
		claim.Data{
			"challenge": "1234", // todo: random
		},
		claim.Issuer(thisService),
		claim.Subject(thisService),
	)
	exitOnError(err)
	log(green, "\t=> Generated Random Authentication Challenge.\n")

	signer := thisService.Signers()[0]
	signer.Sign(challenge)

	log(green, "\t=> Signed Authentication Challenge as: %s\n", thisService.ID())

	log(green, "\t=> Encrypted Authentication Challenge for: %s\n", otherDevice.ID())

	j, err := challenge.MarshalJSON()
	exitOnError(err)
	newline := []byte("\n")
	j = append(j, newline...)

	log(green, "\t=> Sent Authentication Challenge to: %s\n", otherDeviceAttrs["serviceEndpoint"].(string))
	err = printJSON(j)
	exitOnError(err)
	fmt.Fprintf(conn, string(j))

	log(green, "\t=> Waiting for challenge response\n")
	message, _ := bufio.NewReader(conn).ReadString('\n')

	log(green, "=> [5] Received challenge response\n")
	printJSON([]byte(message))

	log(green, "\t=> Decrypted Challenge Response.\n")

	challengeResponse := claimFromJSON(message)
	log(green, "\t=> From: %s\n", challengeResponse.Issuer().ID())
	data := challengeResponse.Data()
	log(green, "\t=> Signed by: %s\n", challengeResponse.Issuer().ID())
	challengeString := data["challenge"]
	if challengeString == "1234" {
		log(green, "\t=> Random Challenge Matched: %s\n", challengeString)
		log(green, "\t=> Authenticated: %s\n", otherDevice.ID())
	} else {
		log(green, "\t=> Not Authenticated: %s\n", otherDevice.ID())
	}

	challenge1String := data["challenge1"]
	log(green, "\t=> PHASE-2 Challenge Included: %s\n", challenge1String)

	log(green, "=> [6] Preparing PHASE-2 Challenge Response:\n")
	challenge1Response, err := claim.New(
		claim.Data{
			"challenge1": challenge1String,
		},
		claim.Issuer(thisService),
		claim.Subject(thisService),
	)
	exitOnError(err)
	log(green, "\t=> Generated PHASE-2 Challenge Response\n")

	signer.Sign(challenge1Response)
	log(green, "\t=> Signed by: %s\n", thisDevice.ID())
	log(green, "\t=> Encrypted for: %s\n", otherDevice.ID())

	j, err = challenge1Response.MarshalJSON()
	exitOnError(err)
	newline = []byte("\n")
	j = append(j, newline...)
	fmt.Printf(green("\t=> Sent challenge response.\n"))
	printJSON(j)
	fmt.Fprintf(conn, string(j))

	// canonicalized := canonicalize(challenge)
	// newline := []byte("\n")
	// canonicalized = append(canonicalized, newline...)
	// fmt.Fprintf(conn, string(canonicalized))

	for {
		// read messages ending in a new line.
		message, _ := bufio.NewReader(conn).ReadString('\n')

		// remove the trailing newline
		message = strings.TrimSuffix(message, "\n")
		// send to socket

		log(green, "=> [7] [%s]: %s\n", otherDevice.ID(), message)
	}
}

func connectWithOckam() {
	log(green, "\n=> Connecting to Ockam:\n")

	ockamNode, err := node.New(node.PeerDiscoverer(http.Discoverer("test.ockam.network", 26657)))
	exitOnError(err)
	log(green, "\t=> Started a new local light node.\n")

	err = ockamNode.Sync()
	exitOnError(err)
	log(green, "\t=> Synced local light node.\n")

	ockamChain = ockamNode.Chain()
	log(green, "\t=> Connected: %s\n", ockamChain.ID())
}

func initializeThisDeviceEntity() {
	log(green, "\n=> Initializing this devices's Ockam entity: \n")
	log(green, "\t=> Local Name: %s\n", *name)

	hostname, err := os.Hostname()
	exitOnError(err)

	thisDevice, err = entity.New(entity.Attributes{
		"name":            name,
		"serviceEndpoint": fmt.Sprintf("%s:%d", hostname, *port),
	}, entity.Signer(initializeSigner(*name)))
	exitOnError(err)

	log(green, "\t=> Initialized Entity: %s\n", thisDevice.ID())
	log(green, "\t=> Ensure Registered: %s\n", thisDevice.ID())
	ensureRegistered(thisDevice)
}

func initializeSigner(name string) *rsa.RSA {
	log(green, "\t=> Initializing RSA Signer: %s\n", name)

	var signer *rsa.RSA
	var content []byte

	var publicKey []byte
	var privateKey []byte

	privateKeyPath := name
	publicKeyPath := name + ".pub"

	_, err := os.Stat(privateKeyPath)
	if err == nil {
		log(green, "\t\t=> Private key found: %s\n", privateKeyPath)

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
		log(green, "\t\t=> Private key not found, generating... \n")

		signer, err = rsa.New()
		exitOnError(err)

		err = ioutil.WriteFile(privateKeyPath, []byte(hex.EncodeToString(signer.PrivateKey())), 0644)
		exitOnError(err)
		log(green, "\t\t=> Generated private key: %s\n", privateKeyPath)

		err = ioutil.WriteFile(publicKeyPath, []byte(signer.PublicKey().Value()), 0644)
		exitOnError(err)
		log(green, "\t\t=> Generated public key: %s\n", publicKeyPath)

	} else {
		exitOnError(err)
	}

	log(green, "\t\t=> Initialized Signer: %s\n", name)
	return signer
}

func ensureRegistered(e ockam.Entity) {
	_, _, err := ockamChain.FetchEntity(e.ID().String())
	if err != nil {
		if err.Error() == "does not exist" {
			log(green, "\t\t=> Registering: %s\n", e.ID())
			_, err = ockamChain.Register(e)
			exitOnError(err)
			time.Sleep(2 * time.Second)
			ensureRegistered(e)
		} else {
			exitOnError(err)
		}
	} else {
		log(green, "\t\t=> Registered: %s\n", e.ID())
	}
}

func exitOnError(err error) {
	if err != nil {
		fmt.Fprintf(os.Stderr, red("%+v\n"), err)
		os.Exit(1)
	}
}

func log(c func(string) string, format string, a ...interface{}) {
	fmt.Printf(c(format), a...)
}

func color(s string, c int) string {
	return fmt.Sprintf("\x1b[0;%dm%s\x1b[0m", c, s)
}

func green(s string) string {
	return color(s, 32)
}

func red(s string) string {
	return color(s, 31)
}

func grey(s string) string {
	return color(s, 30)
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
	if *verbose {
		var prettyJSON bytes.Buffer
		err := json.Indent(&prettyJSON, j, "      ", "  ")
		if err != nil {
			return err
		}
		fmt.Printf("%s\n", string(prettyJSON.Bytes()))
	}
	return nil
}

// https://gist.github.com/taktran/1b691c08216dd30b70bf
func led0On() {
	cmd := "echo gpio | tee /sys/class/leds/led0/trigger"
	_, err := exec.Command("bash", "-c", cmd).Output()
	exitOnError(err)

	cmd = "echo heartbeat | tee /sys/class/leds/led0/trigger"
	_, err = exec.Command("bash", "-c", cmd).Output()
	exitOnError(err)
}

func led0Off() {
	cmd := "echo mmc0 | tee /sys/class/leds/led0/trigger"
	_, err := exec.Command("bash", "-c", cmd).Output()
	exitOnError(err)
}
