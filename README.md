# DIDkit (developing)

DO NOT USE IN PRODUCTION ENVIRONMENT.

<br>
References:
<br>
・https://github.com/spruceid/didkit
<br>
・https://github.com/spruceid/ssi
<br>
<br>

## Generate key

```sh
$ cargo run key generate secp256k1
```

output

```sh
{
  "kty": "EC",
  "crv": "secp256k1",
  "x": "e0ql3JX6Ze-N71NGfrEbOhKnygqjoudXWbczSgct7zM",
  "y": "qT5v_XVlVszareoiFlbAkf-UF-j_lWWbynAwoeqooUQ",
  "d": "PdvF2usIAcov09e04kR_IpTNWMsayaeyiqrD-DyOigU"
}
```

## Create DID

※ only available ION

```sh
$ cargo run did create [DID_METHOD] --update-key [YOUR_UPDATE_KEY_PATH] --recovery-key [YOUR_RECOVERY_KEY_PATH]
```

output

```sh
{
  "didMethod": "ion",
  "value": {
    "sidetreeOperation": {
      "delta": [...],
      "suffixData": [...],
      "type": "create"
    }
  }
}
```
