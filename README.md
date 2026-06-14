# Wise Statements

Node 24 TypeScript script for downloading Wise balance statements as JSON.

## Setup

Run these from the project root:

```sh
npm install
cp .env.example .env
```

Set `WISE_API_TOKEN` in `.env`.

## Scope

This is for Wise business profiles where Wise supports balance statements via personal API tokens.

Wise documents that EU/UK profiles cannot view balance statements via personal API tokens due to PSD2. Personal profiles are not supported by this private-key SCA signing flow.

## Wise SCA key setup

Business balance statements require SCA signing.

Generate a keypair:

```sh
npm run generate-keypair
```

Upload this file in Wise under API tokens / Manage public keys for each business profile you want to use:

```text
keys/wise-public.pem
```

Keep this file local:

```text
keys/wise-private.pem
```

Public keys are profile-specific. A key uploaded for one business profile does not authorize another business profile.

Use a different keypair with:

```sh
npm run statements -- --profile-name "Example Business Ltd" --private-key keys/example-business-private.pem --start 2026-01-01 --end 2026-01-31
```

Upload the matching public key for that profile.

You can also set the default private key path in `.env`:

```env
WISE_PRIVATE_KEY_PATH=keys/wise-private.pem
```

## Usage

List profiles:

```sh
npm run list-profiles
```

This shows e.g.:

```
1) id=12345678, type=PERSONAL, state=VISIBLE, name=John Doe
2) id=87654321, type=BUSINESS, state=VISIBLE, name=JD LLC, role=OWNER
```

Download statements:

```sh
npm run statements -- --start 2026-01-01 --end 2026-01-31
```

Use a specific profile:

```sh
npm run statements -- --profile-id 123456 --start 2026-01-01 --end 2026-01-31
npm run statements -- --profile-name "JD LLC" --start 2026-01-01 --end 2026-01-31
```

Choose currencies:

```sh
npm run statements -- --start 2026-01-01 --end 2026-01-31 --currencies USD,EUR,GBP
```

Choose output directory, statement type, or locale:

```sh
npm run statements -- --start 2026-01-01 --end 2026-01-31 --output-dir statements/january --type FLAT --locale en
```

Statements are written to `statements/`, which is gitignored.

## Options

`npm run statements -- ...` supports:

- `--profile-id ID` to skip the interactive picker and use a specific Wise profile id
- `--profile-name NAME` to use the active profile whose name exactly matches `NAME`
- `--currencies USD,EUR,GBP` to request one or more balance currencies
- `--output-dir DIR` to choose where statement JSON files are written
- `--type COMPACT|FLAT` to select the Wise statement format
- `--locale en` to choose the statement locale sent to Wise
- `--private-key PATH` to override `WISE_PRIVATE_KEY_PATH` for SCA signing

The script also supports:

- `npm run list-profiles` to print the profiles visible to the token
- `npm run generate-keypair` to create a new RSA keypair for Wise SCA signing

## Debugging

Set `WISE_DEBUG=1` to print request flow and SCA diagnostics:

```sh
WISE_DEBUG=1 npm run statements -- --profile-name "Example Business Ltd" --currencies USD --start 2026-01-01 --end 2026-01-31
```

This includes the selected profile id, selected balance id, Wise challenge token, trace ids, and response headers.

If you need to contact Wise support, add `--support-report` to print a paste-ready report on failure:

```sh
WISE_DEBUG=1 npm run statements -- --support-report --profile-name "Example Business Ltd" --currencies USD --start 2026-01-01 --end 2026-01-31
```

This report includes the profile summary, balance id, request URL, challenge token, trace ids, key fingerprint summary, and the final Wise error.
