# Pinned client-schema manifest

`Hop/Resources/xray-client-schema-v26.6.27.json` is generated from the JSON-tagged
configuration structs in Xray-core `v26.6.27` (`45cf2898ab12e97a55dd8f1f3d78d903340bdc9e`).

Regenerate it with:

```sh
scripts/generate-xray-client-schema.sh
```

Verify that the checked-in file is current without modifying it with:

```sh
scripts/generate-xray-client-schema.sh --check
```

The script checks Go `1.26.5`, the exact selected Xray module version, and the
module origin commit before running `XrayBridge/cmd/schema-manifest`. The
generator parses the pinned `infra/conf` Go AST, follows the client-relevant
struct graph, and emits source file/line provenance for each definition. It
then applies reviewed mappings for Xray's `json.RawMessage` unions, custom JSON
unmarshalers, enums, client/server applicability, and Hop's secret, security,
memory, and rejection annotations.

## Deliberate limitations

- This is a versioned validation manifest, not a general-purpose JSON Schema.
  Xray custom unmarshalers accept several equivalent spellings that are
  represented as multi-type fields or notes rather than expanded schemas.
- VLESS Encryption/Auth is a versioned string grammar, so it is preserved and
  core-validated instead of represented as a closed enum.
- TLS fingerprints, cipher-suite names, curve names, and ECH payload syntax are
  delegated to the pinned TLS/uTLS parser because their registries are not
  declared by the `infra/conf` structs.
- Dynamic `RawMessage` account entries are identified by their protocol union.
  The common account structs are included, but final acceptance still requires
  exact parsing by LibXray.
- The manifest records upstream-parsed values even when Hop policy is narrower;
  applicability, notes, and `annotations.rejectedPaths` describe those policy
  restrictions. `XrayConfigBuilder` remains the enforcement point.
