# Zedis

Zedis is a [Redis protocol][redisProtocol] interface for the [0-stor][zeroStor]

![alt text](docs/assets/concept.jpg)

## Supported Redis commands

* `PING`: Pings Zedis
    * reply: Pong
* `QUIT`: Closes the connection
* `AUTH`: authenticates the connection
    * expects: JWT
    * reply OK
* `SET`: Set a value
    * expects: key, value
    * reply: OK
* `GET`: Get a value from a key
    * expects: key
    * reply: key value
* `EXISTS`: Checks if keys exists 
    * expects: space separated list of keys
    * reply: int that represents how many of the keys were found

## Security

### TLS

Zedis can expose 2 TCP ports, one with plaintext traffic and the other with a [TLS][tls] enabled connection.
Certificates can be managed by let's encrypt or by self updating in memory self signed certificates depending on [configuration](#configuration).

The plain TCP port is optional and can be disabled by omitting it from the config file.

### Protected commands

Depending on the configuration, some Redis commands require authentication, these will be authenticated with a [JWT][jwt] from [itsyou.online][iyo].
A JWT for the connection can be set with the AUTH [command](#supported-redis-commands).

The user needs to be member of the the zedis namespace (admin) or write sub organization of the zedis namespace to have permission to `SET` to Zedis and provide that scope in the JWT.
If `GET` requires authentication, the user needs to be admin of the namespace or member of the read sub organization.

e.g. :
```js
// data part of the JWT
{
    ...
    "scope": "user:memberof:zedis_org.zedis_namespace" // admin scope
    ...
}
```

To set which commands require authentication, define them as a comma separated list in the `auth_commands` field in the config file.  
By default, the `SET` command requires authentication.  
If `auth_commands` is set to `none`, none of the commands require authentication.  
If set to `all`, all commands other than `AUTH`, `PING` and `QUIT` require authentication.

## Configuration file

Configuration of Zedis is done through a YAML config file, by default it will be ./config.yaml

```yaml
#zedis specific configuration

port: :6380         #plain tcp port
tls_port: :6381     #tls enabled tcp port
auth_commands: all   # defines the commands that require auth command
jwt_organization: zedis_org      #itsyou.online organization the authenticated used needs to be member of
jwt_namespace: zedis_namespace   #itsyou.online namespace the authenticated used needs to be member of
acme: true          #tls will get it's certificated from let's encrypt
acme_whitelist:     #hostnames let's encrypt is allowed to sign, if empty it will allow all incoming hostnames
    - zedis.org     #only exact matches are currently supported. Subdomains, regexp or wildcard will not match. 
                    # https://godoc.org/golang.org/x/crypto/acme/autocert#HostWhitelist

# configuration for the 0-stor client
zstor_config:
    namespace: thedisk
    datastor:
        shards:
            - 127.0.0.1:12345
            - 127.0.0.1:12346
            - 127.0.0.1:12347
    metastor:
        shards:
            - 127.0.0.1:2379
    pipeline:
        block_size: 4096
        compression:
            mode: default
        encryption:
            private_key: ab345678901234567890123456789012
        distribution:
            data_shards: 2
            parity_shards: 1
```

More information about the 0-stor configuration can be found in the [0-stor client config documentation][0storclient]


[zeroStor]:https://github.com/zero-os/0-stor
[redisProtocol]: https://redis.io/topics/protocol
[jwt]: https://jwt.io/
[tls]: https://en.wikipedia.org/wiki/Transport_Layer_Security
[iyo]: https://github.com/itsyouonline/identityserver/blob/master/docs/oauth2/jwt.md#jwt-json-web-token-support
[0storclient]: https://github.com/zero-os/0-stor/tree/master/client#using-0-stor-client-examples