# Release workflow

The user has authorized pushing and publishing each new application version to GitHub. Treat this as the normal completion workflow for version changes; do not ask for the same permission again.

- Keep the CMake version and Windows resource version consistent.
- Run the applicable local build and tests, prepare matching installation/portable artifacts, and record what was actually verified.
- Commit and push the complete version change to `Hubujiu/SCAU-Link`, then wait for the Windows GitHub Actions checks on that exact source revision to pass.
- Create and push the version tag, sign the update metadata with the existing local signing identity, and publish the complete GitHub Release using the repository scripts. A CI run alone does not publish an application update.
- Verify the public assets, signatures, version and download hashes after publication. Do not replace an already published version with different binaries.
- Keep credentials, private keys, captures, raw school responses and private configuration out of Git and release assets. The existing signing key stays local; never print its contents.
- Do not install a release over the user's running campus client or disconnect the current network as part of publishing.
