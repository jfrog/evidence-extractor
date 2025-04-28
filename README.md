# Evidence verifier

A simple web-based tool to extract content from DSSE (Dead Simple Signing Envelope) payloads.

## Features

- Extract and decode base64-encoded payloads from DSSE envelopes
- Automatic JSON formatting for JSON payloads
- Error handling for invalid inputs
- Modern, responsive UI

## Usage

1. Open `index.html` in your web browser
2. Paste your DSSE envelope JSON into the text area
3. Click "Extract Content" to process the envelope
4. The decoded content will be displayed below the input area

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

Output:
```json
{
    "message": "Hello World"
}
```

## Note

This tool only extracts and decodes the payload content. It does not verify signatures or perform any cryptographic operations. 