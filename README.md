[ [Русская Версия](README.ru.md) ]
# SHADNS
## Current status: Work In Progress!

> pronounced "shadness", means SHA-256 DNS

A DNS-compatible server that automatically matches network addresses with nodes using the electronic digital signature key they use. To work, you need to start the server, specifying the cryptographic key and at least one address of a known network node. The service allows you to find the actual addresses of the network node using the specified cryptographic key, represented as a domain name, by implementing the processing of requests for DNS records of the "A" type. The default root domain to be served by the server is **.sha**.

For classic network clients (such as a browser, email client, and so on), the SHADNS server provides a transparent recursive lookup indistinguishable from DNS. The recursive network search mode is available by default only for local services (127.0.0.0/24) in order to limit the load on lightweight network nodes, but can be extended by replenishing the white list of accepted addresses or enabling recursive search mode for all willing clients.

For external clients (outside the addresses from the white list), the work with the SHADNS server occurs exclusively with the use of electronic digital signatures, the server does not perform a recursive network search, but generates a response based on the data of its automatically replenished address book.

**Applications**

- assistance in remote access to network nodes with dynamic addresses
- standardized base layer for peer-to-peer applications (blockchain, chats, file sharing, etc.)

# Install

Install `shadns` ruby gem:
```
gem install shadns
```


# Usage

Make a cryptographic keys for your node:
```
ssh-keygen -t ed25519 -f ./my_node_key
```

Create and edit the configuration file:
```
shadns-config ./my_node.yml
```

Start SHADNS server:
```
shadns my_node.yml
```

## Contributing: [WIP](CONTRIBUTING.md)

## License: [MIT](LICENSE.md)

## See also

* [DNS]()
* [ECDSA]()
* [Ed25519]()
* [Kademlia]()
* [OpenSSH]()
* [SHA-256]()
