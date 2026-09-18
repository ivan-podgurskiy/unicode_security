# Third-Party Notices

## Unicode data

This package includes generated tables derived from the Unicode Character
Database and Unicode Technical Standard #39, "Unicode Security Mechanisms."
Those data and specifications are copyright Unicode, Inc. and are distributed
under the Unicode License v3 reproduced below. The package includes derived
normalization (including NFC composition), confusables, script, decimal-number,
identifier-property, and profile-property tables
and a provenance manifest for 19 locked sources. The Recommended script set is derived from UAX #31
revision 44, Table 5 (Unicode 18.0.0 proposed). Raw source files
and the normalization conformance corpus are development inputs and are not
included in the Hex package. Profile properties use the pinned UnicodeData.txt
General_Category (including First/Last ranges), PropList.txt White_Space and
Bidi_Control, extracted/DerivedJoiningType.txt Joining_Type, and
IndicSyllabicCategory.txt Vowel_Dependent. NFC composition pairs use
DerivedNormalizationProps.txt Full_Composition_Exclusion and UnicodeData.txt
canonical mappings, with Hangul handled algorithmically per UAX #15 revision 58.

This package pins **draft Unicode 18.0.0** and targets UTS #39 revision 34.
`UnicodeSecurity.data_manifest/0` records the precise source URLs, versions,
draft statuses, byte sizes, and SHA-256 hashes. This attribution does not imply
that Unicode, Inc. endorses the package or that the draft data is final.

The referenced materials and license are available from:

- [UTS #39 revision 34](https://www.unicode.org/reports/tr39/tr39-34.html)
- [UAX #15 revision 58](https://www.unicode.org/reports/tr15/tr15-58.html)
- [UAX #31 revision 44](https://www.unicode.org/reports/tr31/tr31-44.html)
- [Unicode 18.0.0 data](https://www.unicode.org/Public/18.0.0/ucd/)
- [Draft security data](https://www.unicode.org/Public/draft/security/)
- [Unicode License v3](https://www.unicode.org/license.txt)

## Unicode License v3

```text
UNICODE LICENSE V3

COPYRIGHT AND PERMISSION NOTICE

Copyright © 1991-2026 Unicode, Inc.

NOTICE TO USER: Carefully read the following legal agreement. BY
DOWNLOADING, INSTALLING, COPYING OR OTHERWISE USING DATA FILES, AND/OR
SOFTWARE, YOU UNEQUIVOCALLY ACCEPT, AND AGREE TO BE BOUND BY, ALL OF THE
TERMS AND CONDITIONS OF THIS AGREEMENT. IF YOU DO NOT AGREE, DO NOT
DOWNLOAD, INSTALL, COPY, DISTRIBUTE OR USE THE DATA FILES OR SOFTWARE.
Permission is hereby granted, free of charge, to any person obtaining a
copy of data files and any associated documentation (the "Data Files") or
software and any associated documentation (the "Software") to deal in the
Data Files or Software without restriction, including without limitation
the rights to use, copy, modify, merge, publish, distribute, and/or sell
copies of the Data Files or Software, and to permit persons to whom the
Data Files or Software are furnished to do so, provided that either (a)
this copyright and permission notice appear with all copies of the Data
Files or Software, or (b) this copyright and permission notice appear in
associated Documentation.
THE DATA FILES AND SOFTWARE ARE PROVIDED "AS IS", WITHOUT WARRANTY OF ANY
KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT OF
THIRD PARTY RIGHTS.
IN NO EVENT SHALL THE COPYRIGHT HOLDER OR HOLDERS INCLUDED IN THIS NOTICE
BE LIABLE FOR ANY CLAIM, OR ANY SPECIAL INDIRECT OR CONSEQUENTIAL DAMAGES,
OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS,
WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION,
ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THE DATA
FILES OR SOFTWARE.
Except as contained in this notice, the name of a copyright holder shall
not be used in advertising or otherwise to promote the sale, use or other
dealings in these Data Files or Software without prior written
authorization of the copyright holder.
```
