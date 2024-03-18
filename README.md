# Nexus

Nexus is a management wrapper around Slack's [Nebula](https://github.com/slackhq/nebula).
It supports automatic bootstrapping of hosts, certificate renewal and revocation,
lighthouse discovery, as well as pushing and pulling of subnet routes.

## Status of this project

Nexus is a hobby project. In its current state it is usable, but is missing key aspects
to make it truly production ready, such as tests, metrics, and consistent logging.
Expect bugs.

## Design considerations

### Challenges with using standalone Nebula

Nebula provides the tool `nebula-cert` that can be used to create a CA and sign host
certificates. However, it is expected from the user to manage processes that involve
updating information encoded in the certificates, such as updating the groups that
the host belongs to, creating a new certificate for the host, and revoking the old
certificates on all other hosts in the network.

Furthermore, configuring an individual host requires a lot of implicit knowledge
about how the Nebula network is configured. Adding a lighthouse requires to
deploy a configuration change to all Nebula hosts in the network. This is already
inconvenient for small-scale setups, and unsustainable for serious production
workloads. Nexus aims to solve these challenges.

### Out of Scope

Only a subset of Nebula's configuration is managed by Nexus. Most notably, it does not
manage firewall rules, as it is expected that such access restriction is
the responsibility of the operator of the individual host, not the responsibility of
the operator of the overall network.

Similarly, a host that is eligible to route traffic for a specific subnet can publish
these routes, but other Nexus hosts only automatically pull these as `unsafe_routes`
into their own configuration if they are explicitly configured to do so.

## Authentication

Nexus clients authenticate against the central Nexus server via a self-signed TLS client
certificate and/or their MAC address.

### Client certificate

When a Nexus client is started for the first time, it generates a self-signed certificate.
It can from then on prove that it is the owner of the underlying public key. When the
client first registers to the Nexus Server, a client entry is created for that public key,
and the network operator can grant network access to the client that can prove that it
owns that public key.

That means that trust is established by the network operator expecting a Nexus client to
bootstrap at that point in time, and then allowing that access.

Please note that this behavior could be extended in two ways to further automate bootstrapping:

- A certificate with a valid signature can be used instead of a self-signed certificate. A
  reverse proxy for TLS termination can be run in front of Nexus Server that validates
  this certificate and forwards the PEM-encoded certificate in the `X-SSL-CERT` header.
  While this is already supported, it is not yet supported to identify clients based on
  claims in the certificate other than the public key.
- The self-signed certificate can also be based on a private key that is stored in the
  host's Trusted Platform Module (TPM). While not implemented as of yet, this could
  be used to authenticate hosts across the operating system installation process.

### MAC Addresses

Clients can be pre-created using their MAC address. If a request reaches Nexus Server from
an IP in its own local network, an ARPING is sent to determine the MAC address. If this
matches the MAC address that a client was created with, that client's entry is registered
with the public key that was presented through the certificate, as explained above.

This functionality should be considered experimental, as this requires the Nexus Server to be
in the same local network as the client, limiting its usefulness. However, future versions
might support local proxies to a central Nexus Server, with the proxy being able validate
the MAC address as explained above.

## Getting Started

This documentation assumes that you are familiar with the Nebula documentation.

### Creating an admin certificate

Administrator actions, such as assigning clients to networks, are also managed client certificates.
On your workstation, in the folder where you will execute the nexus CLI, create a self-signed
certificate in a `cert/` folder.

```
mkdir cert
openssl req -x509 -newkey rsa:4096 -keyout cert/admin.key.pem -out cert/admin.cert.pem -sha256 -days 3650 -nodes -subj "/C=XX/ST=StateName/L=CityName/O=CompanyName/OU=CompanySectionName/CN=CommonNameOrHostname"
```

The paths above are the default paths the CLI will use for admin client certificates.

### Setting up Nexus Server

```
$ ./nexus serve \
  --addr ":4240" \                          # address to bind to
  --tls \                                   # enable TLS (required if not running behind reverse proxy) 
  --tls.key /path/to/tls.key.pem \          # paths to TLS key and certificate for the HTTP server
  --tls.cert /path/to/tls.cert.pem \
  --ca.key /path/to/ca.key.pem \            # paths to Nebula CA key and cert as created by nebula-cert ca
  --ca.cert /path/to/ca.cert.pem \          # will be automatically generated if it does not exist
  --db.path /path/to/db.sqlite              # Path to sqlite db. Defaults to in-memory for testing purposes.
```

### Determining the admin public key hash

It is not yet implemented to determine your public key hash locally without running a server. To validate the
connection to the server and to retrieve your public key hash, run

```
$ ./nexus \
    --server https://my.nexus.server.example.com:4240 \
    --tls.key cert/admin.key.pem \
    --tls.cert cert/admin.cert.pem \
    --tls.insecureSkipVerify \          # required if server certificate is self-signed
    --tls.name admin

ClientID
5039d1affe1897824809f741fdac66e61a7e94057055a6b0fffed1d5b62ec2f1
```

You can then use that clientID to run Nexus Server with admin permissions granted to that key:

```
$ ./nexus serve \
  --addr ":4240" \
  --tls \
  --tls.key /path/to/tls.key.pem \
  --tls.cert /path/to/tls.cert.pem \
  --ca.key /path/to/ca.key.pem \
  --ca.cert /path/to/ca.cert.pem \
  --db.path /path/to/db.sqlite
  --admins admin=5039d1affe1897824809f741fdac66e61a7e94057055a6b0fffed1d5b62ec2f1
```

### Setting up a lighthouse

Set up a Nebula configuration as per the Nebula docs, but with the following considerations:

- Under `pki`, only `pki.key` is required, and does not need to exist in advance. The Nebula certificate will be created in the same folder automatically.
- Make sure that `lighthouse.am_lighthouse` is set to `true`
- Make sure that the configuration is the only .yaml file in the folder. Nexus works by creating an additional configuration file that is merged with the
  standard one you create.

Run the following:

```
$ ./nexus nebula \
    --server https://my.nexus.server.example.com:4240
    --tls.insecureSkipVerify \
    --network default \
    --config /path/to/config/directory/ \       # Note that this has to be a directory which includes your config.yaml
    --tls.key /path/to/client/tls.key.pem \     # Client TLS certificate and key. Will be automatically created
    --tls.cert /path/to/client/tls.cert.pem \   # if they don't exist.
    --tls.name lighthouse.example.com \         # Value to enter into the "CommonName" field of the TLS certificate.
    --lighthouse.addr 123.123.123.123:4242      # Public address of the lighthouse to advertise
```

After starting, the client will now try to register to the `default` network, but does not have access yet. It
will sit in this state until it does.

### Creating the network

At this point it is advisable to create a `.env` file on your admin workstation to save common parameters.

```
$ cat .env
export NEXUS_SERVER=https://my.nexus.server.example.com:4240
export NEXUS_TLS_INSECURESKIPVERIFY=true
export NEXUS_TLS_KEY=cert/admin.key.pem
export NEXUS_TLS_CERT=cert/admin.cert.pem
```

You can now run `source .env` in a terminal to load these environment variables. For ease of reading, these parameters
will not be repeated in the snippets below.

Run the following command to create the network:

```
$ ./nexus network create \
    --network.name default \
    --network.subnet 10.10.0.0/16
```


### Adding the lighthouse to the network

To identify the lighthouse host currently trying to bootstrap, run

```
$ ./nexus client list
PublicKeyHash                                                           CommonName              HardwareAddress Networks
89d529df5e222e80b8d429cbd1069cb8471a30d4c2ec0d6f784e8fbcc4197bad        lighthouse.example.com
```

**Security Note:** The "CommonName" listed here is the value from the `--tls.name` parameter. Since this is a self-signed
certificate, this value cannot be trusted to identify the host.

To add it to the network, run

```
$ ./nexus network client create \
    --network.name default \
    --client 89d529df5e222e80b8d429cbd1069cb8471a30d4c2ec0d6f784e8fbcc4197bad \
    --addr 10.10.0.1 \                      # Nebula IP to assign. Will be automatically picked if omitted
    --groups lighthouses \                  # Nebula group for firewalling purposes
    --isLighthouse                          # Allow this client to advertise its lighthouse address
```

After the command is completed, the lighthouse you started with `./nexus nebula [...]` should automatically
connect and join the network.

You can validate the configuration Nexus has created by inspecting the generated `zz_default.yaml` file in the
configuration directory.

### Adding more hosts

To add more hosts, simply repeat the steps under "Setting up a lighthouse" and "Adding the lighthouse to the network"
but:

- In the Nebula config, set `lighthouse.am_lighthouse` to false
- Omit the `--lighthouse.addr` from the arguments to `./nexus nebula [...]`
- Omit the `--isLighthouse` parameter from the arguments to `./nexus network client create [...]`
- Instead, pass `--groups` one or multiple times with groups that are more appropriate for that host

## Updating client configuration

If you run `nexus network client update [...]` to update one or multiple properties of the client, such as the
`--groups`, the following will happen:

- The current certificate of the client will be revoked with a grace period of 10 minutes
- The client, checking for updates every five minutes, will retrieve a new certificate and update its config
- After the 10 minutes grace period have passed, the other clients in the network will receive its hash as part
  of a revocation list, and add the certificate hash to `pki.blocklist`.
- Once the original validity of the certificate has passed (90 days from creation), the hash is removed from
  the revocation list again.


## Subnet routes

Clients can also be created with the `--subnets` flag, allowing them to act as routers for non-Nebula networks
that they are a part of:


```
$ ./nexus network client create \
    --subnets 192.168.178.0/24 \
    [...]
```

To *push* them, so that other Nexus clients can discover these routes, the subnets need to be passed to the
`nexus nebula` command:

```
$ ./nexus nebula \
    --push-routes 192.168.178.0/24 \
    [...]
```

As mentioned above, other Nexus clients do not automatically add these routes to their `unsafe_routes` configuration.
This only happens if they are started with the `--pull-routes` flag:

```
$ ./nexus nebula \
    --pull-routes 192.168.178.0/24 \
    [...]
```