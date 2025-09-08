## Summary

Grant is a license compliance tool that reads and audits licenses from container images, SBOM documents, and file system scans.
It returns a deny or pass depending on if the discovered licenses adhere to the user's supplied policy.

### Core Usage:

As a CI operator, I would like my image's SBOM to be searched for permitted/denied licenses.
I can then gate software releases/promotions based on my organizations license compliance.

I will provide a config that allows for certain licenses with a list of packages as exceptions.
These licenses will be in the format of Identifiers found in the spdx license list:
	- [spdx license list](https://spdx.org/licenses/)
	
I want grant to deny with a status code 1 and informative message when my SBOM contains packages with licenses not allowed by my config.

Config:
```
# Default behavior: DENY all licenses except those explicitly permitted
# Default behavior: DENY packages without licenses

# Allowed licenses (glob patterns supported)
allow:
  - MIT
  - MIT-*
  - Apache-2.0
  - Apache-2.0-*
  - BSD-2-Clause
  - BSD-3-Clause
  - BSD-3-Clause-Clear
  - ISC
  - 0BSD
  - Unlicense
  - CC0-1.0

# Software packages to skip license checking entirely (package manager packages)
ignore-packages:
  - github.com/mycompany/*  # Our own Go modules
  - @mycompany/*           # Our own npm packages
  - mycompany-*            # Our own packages with prefix
```

### Open Questions
- How do users want to see unowned files that are Forbidden for an image scan?
- I've been given an SBOM and it does not illustrate the source (directory or OCI image). Are all license equal?

## Commands
### grant check
### grant List
This shows all the licenses as SPDX identifiers from the SPDX license list with the packages as children
```
grant list redis:latest
MIT
	ID p1 declared xxxxx
	ID p2 concluded xxxx

MIT-Modern-Varient
	ID f1 concluded xxx

NPL-1.0
	ID p1 declared xxxx
```

### grant spdx list
List the latest version of the spdx license list
```
grant spdx list <SOME_SPDX_ID>
BSD Zero Clause License			0BSD		
Attribution Assurance License	AAL		
Abstyles License				Abstyles		
Adobe Systems Incorporated...	Adobe-2006		
Adobe Glyph List License	    Adobe-Glyph		
Amazon Digital Services License	ADSL		
Academic Free License v1.1	    AFL-1.1
Academic Free License v1.2		AFL-1.2
Academic Free License v2.0		AFL-2.0
Academic Free License v2.1		AFL-2.1
Academic Free License v3.0		AFL-3.0


grant spdx list --deprecated <-- show deprecated
...
```

#### Notes
// Latest SPDX license list <--- Might be incompatible
// Compare my organization to an older license list

#### SPDX Sub commmands for setting/using the correct list and getting license text
```
grant spdx version set <VERSION-NUMBER> // sets version list
grant spdx version //lists current license list version
grant spdx get <SPDX-LICENSE-ID> // full contents?
```

// describe resource or just some ID from the list output?
```
grant describe package <package_name:version, package_id>
grant describe license <license_name> <-- Show me all the packages for a license
grant describe file <file_name, file_id>
grant describe <SOME-ID>
```

// compliance and query
```
grant check <SOME-SBOM> --config <SOME_GRANT_CONFIG>
grant search <SOME-QUERY> <--
- Deprecated licenses
- SPDX Complex Expressions
- License Confidence Query
- Concluded vs Declared
- I just want to see all GPL
- Diffs between declared and concluded (inconsistencies - p1 declare MIT, p1 found ADOBE)
- All source files that have declarations (divided by ecosystem or laguage?)
- direct dependencies
```

// Third Party Inputs
Third party?---> deps.dev as input directly****

// Syft Not grabbing all of the packages transitively (MOAR LICENSES)
// Syft pre/post (We want pre build syft SBOM to do the transitive dependencies)

// Go build cache --> Syft Sbom --> Grant (Better golang licenses)


### Misc Notes
License Declared vs License Concluded (Looking at the text vs reading the package data)

Pure syft downstream tool

Sometimes this is by package owned files
Sometimes this is by parsing all files
Sometimes this is by parsing all unowned files

Core model of syft
- update license shape to include tags
- Does it exist on package struct or on its metadata
- update file cataloger to open and conclude licenses

#### Third party things
- Thirdparty license directory for distro... <-- These should be associated with the package

#### SPDX License Expressions
License expressions... Probably advanced level:

https://spdx.org/licenses/
https://spdx.github.io/spdx-spec/v2.3/SPDX-license-expressions/

Sometimes found in package metadata where people want to express 
the presence of multiple license

Debian has some shared license location examples

How to handle all licenses in a compound file?

#### SPDX License Identifiers:
https://github.com/anchore/syft/issues/565
https://spdx.dev/ids/

Are packages limited to one concluded and one declared?

Combinations
- Declared can have a concluded
- If not declated we can still find concluded via owned files
- If declared if might not be able to conclude (Found Nothing?)

Image:
- Owned vs unknowned is imporant

Dir:
- Nothing is owned so the file cataloger does the work

Files should only be concluded

Go over all files?
- What's the hueristic for this?
- only visit `LICENSE` named files?
- check runtime for large SBOM file reads

Does Concluded comes from resolving the file itself as contents of a license?
Does Declared or Concluded comes from reading SPDX IDS from the header of a file?
