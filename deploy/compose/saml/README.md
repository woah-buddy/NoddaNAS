# SAML files

Mounted read-only into the FrontDir container at `/etc/frontdir/saml`. Use it for:

| File | Setting in `../.env` | Notes |
|---|---|---|
| IdP metadata XML (if your IdP has no metadata URL) | `SAML_IDP_METADATA_FILE=/etc/frontdir/saml/idp-metadata.xml` | Use instead of `SAML_IDP_METADATA_URL`, not with it |
| SP private key (optional) | `SAML_SP_KEY_FILE=/etc/frontdir/saml/sp.key` | `sudo chown 65532:65532 sp.key && sudo chmod 0400 sp.key` |
| SP certificate (optional) | `SAML_SP_CERT_FILE=/etc/frontdir/saml/sp.crt` | Set both or neither |

Everything in this directory except this README is ignored by git, so a private key cannot be
committed by accident. Back it up with the rest of `deploy/compose` (see
`docs/DISASTER_RECOVERY.md`).
