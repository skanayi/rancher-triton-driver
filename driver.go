package main

import (
	"context"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"os"
	"path"

	"strings"
	"time"

	"github.com/docker/machine/libmachine/drivers"
	"github.com/docker/machine/libmachine/engine"
	"github.com/docker/machine/libmachine/log"
	"github.com/docker/machine/libmachine/mcnflag"
	"github.com/docker/machine/libmachine/mcnutils"
	"github.com/docker/machine/libmachine/state"
	vapi "github.com/hashicorp/vault/api"

	"github.com/joyent/triton-go"
	"github.com/joyent/triton-go/authentication"
	"github.com/joyent/triton-go/compute"
)

const (
	driverName = "triton"
	flagPrefix = driverName + "-"
	// SDC_ is for historical reasons
	envPrefix = "SDC_"
)

var (
	defaultTritonAccount = ""
	defaultTritonKeyPath = "/id_rsa"
	defaultTritonKeyId   = ""
	defaultTritonUrl     = ""

	// https://docs.joyent.com/public-cloud/instances/virtual-machines/images/linux/debian#debian-8
	defaultTritonImage    = "d676ebb3"
	defaultTritonPackage  = "vm-1cpu-6m-70d-gpc"
	defaultSSHUser        = "root"
	defaultVaultUrl       = ""
	defaultVaultNameSpace = ""
	defaultKeyPathInVault = ""
	defaultVaultToken     = ""
)

type Driver struct {
	*drivers.BaseDriver

	// authentication/access parameters
	TritonAccount string
	TritonKeyPath string
	TritonKeyId   string
	TritonUrl     string

	// machine creation parameters
	TritonImage   string
	TritonPackage string

	// machine state
	TritonMachineId string
	VaultUrl        string
	VaultNameSpace  string
	VaultToken      string
	VaultKeyPath    string
}

// SetConfigFromFlags configures the driver with the object that was returned by RegisterCreateFlags
func (d *Driver) SetConfigFromFlags(opts drivers.DriverOptions) error {
	d.TritonAccount = opts.String(flagPrefix + "account")
	d.TritonKeyPath = opts.String(flagPrefix + "key-path")
	d.TritonKeyId = opts.String(flagPrefix + "key-id")
	d.TritonUrl = opts.String(flagPrefix + "url")

	d.TritonImage = opts.String(flagPrefix + "image")
	d.TritonPackage = opts.String(flagPrefix + "package")

	d.SSHUser = opts.String(flagPrefix + "ssh-user")

	d.VaultUrl = opts.String(flagPrefix + "vault-server")
	d.VaultKeyPath = opts.String(flagPrefix + "vault-key-path")
	d.VaultToken = opts.String(flagPrefix + "vault-token")
	d.VaultNameSpace = opts.String(flagPrefix + "vault-namespace")
	d.SetSwarmConfigFromFlags(opts)

	if d.TritonAccount == "" {
		return fmt.Errorf("%s driver requires the --%saccount/%sACCOUNT option", driverName, flagPrefix, envPrefix)
	}

	if d.TritonKeyId == "" {
		return fmt.Errorf("%s driver requires the --%skey-id/%sKEY_ID option", driverName, flagPrefix, envPrefix)
	}
	if d.TritonUrl == "" {
		return fmt.Errorf("%s driver requires the --%surl/%sURL option", driverName, flagPrefix, envPrefix)
	}

	if d.TritonImage == "" {
		return fmt.Errorf("%s driver requires the --%simage option", driverName, flagPrefix)
	}
	if d.TritonPackage == "" {
		return fmt.Errorf("%s driver requires the --%spackage option", driverName, flagPrefix)
	}
	if d.VaultKeyPath == "" {
		return fmt.Errorf("%s driver requires the --%s option", driverName, flagPrefix)
	}
	if d.VaultNameSpace == "" {
		return fmt.Errorf("%s driver requires the --%s option", driverName, flagPrefix)
	}
	if d.VaultUrl == "" {
		return fmt.Errorf("%s driver requires the --%s option", driverName, flagPrefix)
	}
	return nil
}

// GetCreateFlags returns the mcnflag.Flag slice representing the flags that can be set, their descriptions and defaults.
func (d *Driver) GetCreateFlags() []mcnflag.Flag {
	return []mcnflag.Flag{
		mcnflag.StringFlag{
			EnvVar: envPrefix + "URL",
			Name:   flagPrefix + "url",
			Usage:  "URL of the CloudAPI endpoint",
			Value:  defaultTritonUrl,
		},
		mcnflag.StringFlag{
			EnvVar: envPrefix + "ACCOUNT",
			Name:   flagPrefix + "account",
			Usage:  "Login name/username",
			Value:  defaultTritonAccount,
		},
		mcnflag.StringFlag{
			EnvVar: envPrefix + "KEY_ID",
			Name:   flagPrefix + "key-id",
			Usage:  fmt.Sprintf(`The fingerprint of $%sKEY_PATH (ssh-keygen -l -E md5 -f $%sKEY_PATH | awk '{ gsub(/^[^:]+:/, "", $2); print $2 }')`, envPrefix, envPrefix),
			Value:  defaultTritonKeyId,
		},
		mcnflag.StringFlag{
			EnvVar: envPrefix + "KEY_PATH",
			Name:   flagPrefix + "key-path",
			Usage:  fmt.Sprintf("A path to an SSH private key file that has been added to $%sACCOUNT", envPrefix),
			Value:  defaultTritonKeyPath,
		},

		mcnflag.StringFlag{
			Name:  flagPrefix + "image",
			Usage: `VM image to provision ("debian-8", "debian-8@20150527", "ca291f66", etc)`,
			Value: defaultTritonImage,
		},
		mcnflag.StringFlag{
			Name:  flagPrefix + "package",
			Usage: `VM instance size to create ("g3-standard-0.25-kvm", "g3-standard-0.5-kvm", etc)`,
			Value: defaultTritonPackage,
		},
		mcnflag.StringFlag{
			EnvVar: envPrefix + "SSH_USER",
			Name:   flagPrefix + "ssh-user",
			Usage:  "Triton SSH user",
			Value:  defaultSSHUser,
		},

		mcnflag.StringFlag{
			EnvVar: envPrefix + "VAULT_SERVER",
			Name:   flagPrefix + "vault-server",
			Usage:  "Vault server URL",
			Value:  defaultVaultUrl,
		},
		mcnflag.StringFlag{
			EnvVar: envPrefix + "VAULT_NAME_SPACE",
			Name:   flagPrefix + "vault-namespace",
			Usage:  "Vault namespace",
			Value:  defaultVaultNameSpace,
		},
		mcnflag.StringFlag{
			EnvVar: envPrefix + "VAULT_TOKEN",
			Name:   flagPrefix + "vault-token",
			Usage:  "Vault token",
			Value:  defaultVaultToken,
		},
		mcnflag.StringFlag{
			EnvVar: envPrefix + "VAULT_KEY_PATH",
			Name:   flagPrefix + "vault-key-path",
			Usage:  "Vault key path",
			Value:  defaultKeyPathInVault,
		},
	}
}

func (d Driver) client() (*compute.ComputeClient, error) {

	keyMaterial := d.TritonKeyPath
	log.Debugf("triton key path is ", keyMaterial)
	keyID := d.TritonKeyId
	accountName := d.TritonAccount
	userName := ""
	var signer authentication.Signer
	var err error

	var keyBytes []byte
	if _, err := os.Stat(keyMaterial); err == nil {
		keyBytes, err = ioutil.ReadFile(keyMaterial)
		if err != nil {
			log.Errorf("Error reading key material")

		}
		block, _ := pem.Decode(keyBytes)
		if block == nil {
			log.Errorf("key not found")
		}

		if block.Headers["Proc-Type"] == "4,ENCRYPTED" {
			log.Errorf("password protected")
		}

	} else {
		keyBytes = []byte(keyMaterial)
	}

	input := authentication.PrivateKeySignerInput{
		KeyID:              keyID,
		PrivateKeyMaterial: keyBytes,
		AccountName:        accountName,
		Username:           userName,
	}

	signer, err = authentication.NewPrivateKeySigner(input)
	if err != nil {
		log.Errorf("Error Creating SSH Private Key Signer")

	}

	config := &triton.ClientConfig{

		TritonURL:   d.TritonUrl,
		AccountName: accountName,
		Username:    userName,
		Signers:     []authentication.Signer{signer},
	}

	c, err := compute.NewClient(config)
	if err != nil {
		log.Errorf("compute new client creatin failed")

	}
	return c, err
}

func (d *Driver) getMachine() (*compute.Instance, error) {
	c, err := d.client()
	if err != nil {
		return nil, err
	}
	machine, err := c.Instances().Get(context.Background(), &compute.GetInstanceInput{
		ID: d.TritonMachineId,
	})
	if err != nil {
		return nil, err
	}

	log.Debugf("machine name: %s", machine.Name)

	// update d.IPAddress since we know the value (saves later work)
	d.IPAddress = machine.PrimaryIP

	return machine, nil
}

func NewDriver(hostName, storePath string) Driver {
	return Driver{
		TritonAccount: defaultTritonAccount,
		TritonKeyPath: defaultTritonKeyPath,
		TritonKeyId:   defaultTritonKeyId,
		TritonUrl:     defaultTritonUrl,

		BaseDriver: &drivers.BaseDriver{
			MachineName: hostName,
			StorePath:   storePath,
			SSHUser:     defaultSSHUser,
		},
	}
}

// https://github.com/docker/machine/blob/v0.7.0/libmachine/drivers/drivers.go
// https://github.com/docker/machine/blob/v0.7.0/libmachine/drivers/base.go

// Create a host on Triton using the driver's CLI/environ config
func (d *Driver) Create() error {

	d.SSHKeyPath = path.Join(d.StorePath, "machines", d.GetMachineName(), "id_rsa")
	if err := mcnutils.CopyFile(d.TritonKeyPath, d.SSHKeyPath); err != nil {
		log.Errorf("error copying ssh key to machine directory")

	}

	c, err := d.client()
	if err != nil {
		return err
	}

	input := &compute.CreateInstanceInput{
		Name:    d.MachineName,
		Image:   d.TritonImage,
		Package: d.TritonPackage,
	}
	machine, err := c.Instances().Create(context.Background(), input)
	if err != nil {
		return err
	}

	d.TritonMachineId = machine.ID

	return nil
}

// https://github.com/joyent/node-triton/blob/aeed6d91922ea117a42eac0cef4a3df67fbfed2f/lib/common.js#L306
func uuidToShortId(s string) string {
	return strings.SplitN(s, "-", 2)[0]
}
func iso8859(s string) (time.Time, error) {
	return time.Parse(time.RFC3339, s)
}

// PreCreateCheck allows for pre-create operations to make sure a driver is
// ready for creation
func (d *Driver) PreCreateCheck() error {
	//get required secrets from vault
	err := d.GenerateKeysFromVault()
	if err != nil {
		return err
	}

	c, err := d.client()
	if err != nil {
		return err
	}

	_, err = c.Ping(context.Background())
	if err != nil {
		return err
	}

	_, err = c.Images().Get(context.Background(), &compute.GetImageInput{
		ImageID: d.TritonImage,
	})
	if err != nil {
		// apparently isn't a valid ID, but might be a name like "debian-8" (so
		// let's do a lookup)
		// https://github.com/joyent/node-triton/blob/aeed6d91922ea117a42eac0cef4a3df67fbfed2f/lib/tritonapi.js#L368
		nameVersion := strings.SplitN(d.TritonImage, "@", 2)
		name, version := nameVersion[0], ""
		if len(nameVersion) == 2 {
			version = nameVersion[1]
		}

		listInput := &compute.ListImagesInput{}
		listInput.State = "all"
		if version != "" {
			listInput.Name = name
			listInput.Version = version
		}

		images, imagesErr := c.Images().List(context.Background(), listInput)
		if imagesErr != nil {
			return imagesErr
		}
		nameMatches, shortIdMatches := []*compute.Image{}, []*compute.Image{}
		for _, image := range images {
			if name == image.Name {
				nameMatches = append(nameMatches, image)
			}
			if name == uuidToShortId(image.ID) {
				shortIdMatches = append(shortIdMatches, image)
			}
		}
		if len(nameMatches) == 1 {
			log.Infof("resolved image %q to %q (exact name match)", d.TritonImage, nameMatches[0].ID)
			d.TritonImage = nameMatches[0].ID
		} else if len(nameMatches) > 1 {
			mostRecent := nameMatches[0]
			published := mostRecent.PublishedAt

			for _, image := range nameMatches[1:] {
				newPublished := image.PublishedAt
				if published.Before(newPublished) {
					mostRecent = image
					published = newPublished
				}
			}
			log.Infof("resolved image %q to %q (most recent of %d name matches)", d.TritonImage, mostRecent.ID, len(nameMatches))
			d.TritonImage = mostRecent.ID
		} else if len(shortIdMatches) == 1 {
			log.Infof("resolved image %q to %q (exact short id match)", d.TritonImage, shortIdMatches[0].ID)
			d.TritonImage = shortIdMatches[0].ID
		} else {
			if len(shortIdMatches) > 1 {
				log.Warnf("image %q is an ambiguous short id", d.TritonImage)
			}
			return err
		}
	}

	// GetPackage (and CreateMachine) both support package names and UUIDs interchangeably
	pkgInput := &compute.GetPackageInput{
		ID: d.TritonPackage,
	}
	if _, err := c.Packages().Get(context.Background(), pkgInput); err != nil {
		return err
	}

	return nil
}

func (d *Driver) GenerateKeysFromVault() error {

	log.Info("calling  vault api")
	vClient, err := vapi.NewClient(vapi.DefaultConfig())
	if err != nil {
		log.Errorf("error occured while initiating api", err)
		return err
	}

	err = vClient.SetAddress(d.VaultUrl)
	if err != nil {
		log.Errorf("error setting vault address", err)
		return err
	}
	vClient.SetNamespace(d.VaultNameSpace)

	if err != nil {
		log.Errorf("error setting vault name space")
		return err

	}

	vClient.SetToken(d.VaultToken)
	id_rsa_data, err := vClient.Logical().Read("kv/data/" + path.Dir(d.VaultKeyPath))
	if err != nil {
		log.Errorf("error while reading secret %v", err)
	}
	data := (id_rsa_data.Data)["data"]
	ds := data.(map[string]interface{})
	f, err := os.Create("/id_rsa")
	if err != nil {
		log.Errorf("error occured while creating key file %v", err)
	}
	defer f.Close()
	_, err = f.WriteString(ds[(path.Base(d.VaultKeyPath))].(string))
	if err != nil {
		log.Errorf("error occured while writing key file %v", err)
	}
	err = os.Chmod("/id_rsa", 0600)
	if err != nil {
		log.Errorf("error occured while setting permission on key file %v", err)
	}
	return err
}

// DriverName returns the name of the driver
func (d *Driver) DriverName() string {
	return driverName
}

// GetIP returns an IP or hostname that this host is available at
// e.g. 1.2.3.4 or docker-host-d60b70a14d3a.cloudapp.net
func (d *Driver) GetIP() (string, error) {
	if d.IPAddress != "" {
		return d.IPAddress, nil
	}
	machine, err := d.getMachine()
	if err != nil {
		return "", err
	}
	return machine.PrimaryIP, nil
}

// GetSSHHostname returns hostname for use with ssh
func (d *Driver) GetSSHHostname() (string, error) {
	return d.GetIP()
}

// GetURL returns a Docker compatible host URL for connecting to this host
// e.g. tcp://1.2.3.4:2376
func (d *Driver) GetURL() (string, error) {
	if err := drivers.MustBeRunning(d); err != nil {
		return "", err
	}

	ip, err := d.GetIP()
	if err != nil {
		return "", err
	}

	return fmt.Sprintf("tcp://%s:%d", ip, engine.DefaultPort), nil
}

func (d *Driver) GetSSHKeyPath() string {

	return d.TritonKeyPath
}

// GetState returns the state that the host is in (running, stopped, etc)
//
// https://github.com/docker/machine/blob/v0.7.0/libmachine/state/state.go
func (d *Driver) GetState() (state.State, error) {
	machine, err := d.getMachine()
	if err != nil {
		return state.Error, err
	}

	// https://github.com/joyent/smartos-live/blob/master/src/vm/man/vmadm.1m.md#vm-states
	switch machine.State {
	case "configured", "provisioning":
		return state.Starting, nil
	case "failed", "receiving":
		return state.Error, nil
	case "running":
		return state.Running, nil
	case "shutting_down", "stopping":
		return state.Stopping, nil
	case "down", "stopped":
		return state.Stopped, nil
	}

	return state.Error, fmt.Errorf("unknown Triton instance state: %s", machine.State)
}

// Kill stops a host forcefully
func (d *Driver) Kill() error {
	return d.Stop()
}

// Remove a host
func (d *Driver) Remove() error {
	c, err := d.client()
	if err != nil {
		return err
	}

	ctx := context.Background()
	input := &compute.DeleteInstanceInput{
		ID: d.TritonMachineId,
	}
	return c.Instances().Delete(ctx, input)
}

// Restart a host. This may just call Stop(); Start() if the provider does not
// have any special restart behaviour.
func (d *Driver) Restart() error {
	c, err := d.client()
	if err != nil {
		return err
	}

	ctx := context.Background()
	input := &compute.RebootInstanceInput{
		InstanceID: d.TritonMachineId,
	}
	return c.Instances().Reboot(ctx, input)
}

// Start a host
func (d *Driver) Start() error {
	c, err := d.client()
	if err != nil {
		return err
	}

	ctx := context.Background()
	input := &compute.StartInstanceInput{
		InstanceID: d.TritonMachineId,
	}
	return c.Instances().Start(ctx, input)
}

// Stop a host gracefully
func (d *Driver) Stop() error {
	c, err := d.client()
	if err != nil {
		return err
	}

	ctx := context.Background()
	input := &compute.StopInstanceInput{
		InstanceID: d.TritonMachineId,
	}
	return c.Instances().Stop(ctx, input)
}
