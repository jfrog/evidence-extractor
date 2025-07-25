# A Free DSSE Attestation Online Decoder Tool

A simple web-based tool to extract content from DSSE (Dead Simple Signing Envelope) payloads and validate its signing using a public key.

## Features

- Extract and decode base64-encoded payloads from DSSE envelopes
- Automatic JSON formatting for JSON payloads
- Signing verification using uploaded/pasted public key
- Error handling for invalid inputs


## Usage

You are welcomed to use the tool on https://dsse.io/

### Usage

1. Paste your DSSE envelope JSON into the text area
3. Potentially paste or upload your public key
3. Click "Extract & Verify" to process the envelope
4. The decoded content will be displayed on the right side of the tool along with its signature verification result
5. Alternatively if you have a sigstore bundle, you are welcomed to upload it into the Sigstore Bundle Input tab, and we will extract the DSSE payload from it and also attempt to verify its transparency log entry against sigstore transparency log, if that is available

## DSSE Envelope Format

The tool expects a DSSE envelope in the following format:

```json
{
    "payload": "base64EncodedContent",
    "payloadType": "application/json",
    "signatures": [...]
}
```

## Example

Input:
```json
{
    "payload": "eyJtZXNzYWdlIjoiSGVsbG8gV29ybGQifQ==",
    "payloadType": "application/json",
    "signatures": []
}
```

## Public key

The tool expects a valid public key (RSA/PGP)
Notice that you do not upload/paste keys with \n, only newlines

## RSA Example

```
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA07f3tJM904857fh439f7
...
2lZw/MW6Gp2Mi7nmo7l3XvSd5PwhCIpxnCbL9ag680+Bht//467gn49f67ng5nko
nwIDAQAB
-----END PUBLIC KEY-----
```

## PGP Example

```
-----BEGIN PGP PUBLIC KEY BLOCK-----

mQENBGSG4akBCADGNqHvbIwcEKybDeaBBnhzJceLN8bja5gn65n65e5r6ne9nOsJ
hfVpopyd1TwvwEKwkiPHX1wpXMveS2EQ0sqxKiYmkcqaXalEio8/5TvCzBmg71kD
+5V5eIYXdbZ9nRhwno831xhNiisn1/VWfMWgATags71d1gEA/k68+586gn58k/dl
...
X2mNxPWgSPLCYG7nC/XkCXSJ2lBkpKFYxNy1riXyoDZTKMA+8765j+UpWZqEGLNs
567g59wg67n58g6n5n/4yFCS4i8BWCW0JT67/d5DE4G974=
=l2C3
-----END PGP PUBLIC KEY BLOCK-----
```

## Dependencies

OpenPGP.js  https://www.npmjs.com/package/openpgp (licensed under https://www.gnu.org/licenses/lgpl-3.0.en.html)

Node-Forge (forge.js) https://www.npmjs.com/package/node-forge (license under BSD License/GNU General Public License (GPL) Version 2 )

@peculiar/x509 https://www.npmjs.com/package/@peculiar/x509 (license under https://github.com/PeculiarVentures/x509/blob/master/LICENSE)

starkbank-ecdsa https://www.npmjs.com/package/starkbank-ecdsa (license under https://github.com/starkbank/ecdsa-node/blob/master/LICENSE)

## Note

This tool only verifies RSA, PGP, and ECDSA signatures. 

