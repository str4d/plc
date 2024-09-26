# plc: Key management for DID PLC identities

`plc` is a tool for managing DID PLC identities. The end goal is to enable users
to add and manage YubiKeys as backup rotation keys.

The tool is currently a work-in-progress and may change incompatibly at any time.

The DID PLC specification is at [web.plc.directory](https://web.plc.directory/spec/v0.1/did-plc).

## Installation

| Environment | CLI command |
|-------------|-------------|
| Cargo (Rust 1.65+) | `cargo install --git https://github.com/str4d/plc` |

## Usage

### Key management

Currently only key inspection is implemented:

```
$ plc keys list bsky.app
Not currently authenticated to bsky.app; can't fetch PDS keys

Account did:plc:z72i7hdynmk6r22z27h6tvur
- Primary handle: @bsky.app
- PDS: https://puffball.us-east.host.bsky.network
- Signing key: Unknown (Secp256k1): 043249d921a1da482dc7117e9451bf2ae48ef641dc87bd9c9ea3648f3e81cce2494474cc0a80053c9be012d049a80b0ededd4064670024a8ce8a1b5e25a5655b52
- 2 rotation keys:
  - [0] Unknown (Secp256k1): 0425f4891e63128b8ab689e862b8e11428f24095e3e57b9ea987eb70d1b59af9dfe8113ffd3dcdd3e15ac5415b6282ec12b627d06c7cdead1e3ec1887680948243
  - [1] Unknown (Secp256k1): 048fe3769f5055088b448ca064bcecd7b6844239c355c98d4556d5c9c8c522de784fdc4cd480dc7b99d505243ec026409569a69842dbae649940cf7e8496efa31d
```

### DID inspection

You can list the currently-active operations for a DID:

```
$ plc ops list bsky.app
Account did:plc:z72i7hdynmk6r22z27h6tvur

Initial state:
- Rotation keys:
  - [0] did:key:zQ3shhCGUqDKjStzuDxPkTxN6ujddP4RkEKJJouJGRRkaLGbg
  - [1] did:key:zQ3shpKnbdPx3g3CmPf5cRVTPe1HtSwVn5ish3wSnDPQCbLJK
- Verification methods:
  - atproto: did:key:zQ3shXjHeiBuRCKmM36cuYnm7YEMzhGnCmCyW92sRJ9pribSF
- Also-known-as:
  - [0] at://bluesky-team.bsky.social
- Services:
  - atproto_pds: AtprotoPersonalDataServer = https://bsky.social

Update 1:
- Changed Also-known-as[0] to at://bsky.app

Update 2:

Update 3:
- Changed verification method atproto to did:key:zQ3shQo6TF2moaqMTrUZEM1jeuYRQXeHEx4evX9751y2qPqRA
- Changed service atproto_pds endpoint to https://puffball.us-east.host.bsky.network

Current state:
- Rotation keys:
  - [0] did:key:zQ3shhCGUqDKjStzuDxPkTxN6ujddP4RkEKJJouJGRRkaLGbg
  - [1] did:key:zQ3shpKnbdPx3g3CmPf5cRVTPe1HtSwVn5ish3wSnDPQCbLJK
- Verification methods:
  - atproto: did:key:zQ3shQo6TF2moaqMTrUZEM1jeuYRQXeHEx4evX9751y2qPqRA
- Also-known-as:
  - [0] at://bsky.app
- Services:
  - atproto_pds: AtprotoPersonalDataServer = https://puffball.us-east.host.bsky.network
```

`plc` can also validate the audit log provided by [plc.directory](https://plc.directory):

```
$ plc ops audit bsky.app
Audit log for bsky.app is valid!
```

## License

Licensed under either of

 * Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or
   http://www.apache.org/licenses/LICENSE-2.0)
 * MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally
submitted for inclusion in the work by you, as defined in the Apache-2.0
license, shall be dual licensed as above, without any additional terms or
conditions.
