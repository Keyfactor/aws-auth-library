# CI/CD

```mermaid
flowchart TD
    DEV([Developer])

    DEV -->|push to any branch| BUILD_T
    DEV -->|open PR targeting release-X.Y\nor push to open PR| RC_T
    DEV -->|merge PR into release-X.Y| REL_T

    subgraph BUILD_T ["build.yml — all branches"]
        B1[Restore] --> B2[Build]
    end

    subgraph RC_T ["pr-prerelease.yml — PR → release-X.Y"]
        direction TB
        RC_V["Z  =  highest non-RC vX.Y.* patch  +  1
N  =  count of existing vX.Y.Z-rc.* tags"]
        RC_V --> RC1[Restore → Build → Pack\nvX.Y.Z-rc.N]
        RC1  --> RC2[Push tag vX.Y.Z-rc.N\nto PR head SHA]
        RC2  --> RC3[GitHub Prerelease]
        RC2  --> RC4[NuGet Package]
    end

    subgraph REL_T ["release.yml — push to release-X.Y"]
        direction TB
        R_V["Z  =  highest non-RC vX.Y.* patch  +  1\n(RC tags ignored)"]
        R_V --> R1[Restore → Build → Pack\nvX.Y.Z]
        R1  --> R2[Push tag vX.Y.Z]
        R2  --> R3[GitHub Release]
        R2  --> R4[NuGet Package]
    end
```

## Example lifecycle

```mermaid
timeline
    title PR targeting release-1.0 (latest tag v1.0.0)
    PR opened       : v1.0.1-rc.0 prerelease created
    Push to PR      : v1.0.1-rc.1 prerelease created
    Push to PR      : v1.0.1-rc.2 prerelease created
    PR merged       : v1.0.1 release created
    Next PR opened  : v1.0.2-rc.0 prerelease created
```

## Versioning rules

| Component | Rule |
|---|---|
| `Z` (patch) | Highest non-RC `vX.Y.*` tag + 1. Zero if no releases exist yet for this `X.Y`. |
| `N` (RC int) | Count of existing `vX.Y.Z-rc.*` tags. Zero-based — resets to 0 each time `Z` advances. |
| Tag scope | `vX.Y.*` glob is anchored to the exact major and minor from the branch name. Tags from other `X.Y` series are invisible. |
| RC tags | Excluded from `Z` computation in both workflows. Only shipped releases drive the next patch number. |
