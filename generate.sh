#!/bin/sh
# Regenerate the ConfigBroker machine-verifiable artefacts:
#
#   out/resolved.env          the resolved config (secrets in authorised slots)
#   out/audit.log             the audit trail (PUBLIC data only, no secret values)
#   sbom/manifest.json        the capability manifest (declassify sites + surface
#                             + the Net restrict_to host)
#   sbom/sbom.cyclonedx.json  CycloneDX 1.5 SBOM with the manifest embedded
#   sbom/sbom.spdx.json       SPDX 2.3 SBOM companion
#   sbom/provenance.slsa.json SLSA build provenance
#
# The resolved config and the audit log are produced by RUNNING
# ConfigBroker; the SBOM family is EMITTED BY THE COMPILER from the same
# source. Together they are the attestation: the program states the claim
# (no secret leaks; only the allowlisted host is reachable), the compiler
# proves it (information-flow analysis + the capability surface, including
# the Net restrict_to host, in the SBOM).
#
# The run is REPRODUCIBLE and OFFLINE. ConfigBroker attempts the upstream
# fetch (exercising the attenuation gate) and, with no live upstream,
# falls back to the local vault fixture in data/vault.tsv, so the output
# is deterministic without a network. See README "What runs live vs
# offline".
#
# Determinism of the SBOMs comes from SOURCE_DATE_EPOCH
# (reproducible-builds.org): the compiler stamps the SBOM build time from
# this fixed instant, so the artefacts are byte-reproducible. Bump it by
# writing a new UTC epoch to sbom/SOURCE_DATE_EPOCH and rerunning.
#
# Run all Capa invocations through the LOCAL compiler:
#     python -m capa ...   (from a checkout of the Capa compiler on PATH)
# The examples below assume `capa` resolves to that build.
set -e

SOURCE_DATE_EPOCH="$(tr -d '\r' < sbom/SOURCE_DATE_EPOCH)"
export SOURCE_DATE_EPOCH

mkdir -p out sbom

# Run the resolver (Python backend) to produce the config + audit log.
capa --run configbroker.capa

# Emit the compiler-side proof artefacts.
capa --manifest   configbroker.capa > sbom/manifest.json
capa --cyclonedx  configbroker.capa > sbom/sbom.cyclonedx.json
capa --spdx       configbroker.capa > sbom/sbom.spdx.json
capa --provenance configbroker.capa > sbom/provenance.slsa.json

echo "regenerated out/ and sbom/ (SOURCE_DATE_EPOCH=$SOURCE_DATE_EPOCH)"
