## Summary

Grant is a license compliance tool that reads and audits license from container images, SBOM documents, and directory scans.
It generates a pass or fail check depending on if the read licenses adhear to the user's supplied rulesjk

### Syft Updates Needed to Support Grant

- [Google String Classifier License](https://github.com/google/licenseclassifier/tree/main/stringclassifier)

Syft's core elements of files and packages should be enhanced to include more information for grant's processing:

For more details on this redesign see [Syft Licesnse Revamp](https://github.com/anchore/syft/issues/1577).

It's important licenses be included in both core types. 

For image scans packages are most important. Syft can read a package managers declared license and then use the `String Classifier` to conclude that the declared license exists and is accurate.

For direcotry scans files will be the most important. Directory scans have no concept of owned files from a package manager. Files should be read and licenses concluded based on the string classifer.

#### Grant Notes on data shape
- Pay attention to syft compatibility when shape changes
- Our decode implicitly knows all previous versions (check this)
- cyclonedx format needs to be examined for compatibility (possibly show warning)

### Stories:

As a CI operator, I would like my image's SBOM to be searched for permitted/denied licenses
so that I may gate software based on my organizations license compliance.

I will provide a config of either allow list or deny list license.
These license will be in the format of Identifiers found in the spdx license list:
	- [spdx license list](https://spdx.org/licenses/)
	
I want grant to fail with a status code 1 and informative message when my SBOM contains licenses not permitted by my organization.

### Questions

- How do I want to see unowned files that are Forbidden for an image scan?
- I've been given an SBOM and it does not illustrate the source (directory or OCI image). Are all license equal?


### Command CLI Design
`SOME-INPUT = sbom, dir:., registry:alpine:latest`

List all the license for a given input

##### Grant List && Grant SPDX

This shows all the licenses as identifiers from the SPDX license list with the packages and ID as children
```
grant license list <SOME-INPUT>
MIT
	ID p1 declared xxxxx
	ID p2 concluded xxxx

MIT-Modern-Varient
	ID f1 concluded xxx

NPL-1.0
	ID p1 declared xxxx
```

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


#### Notes
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
