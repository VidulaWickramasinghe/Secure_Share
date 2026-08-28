# Repository landing-page images

The banner and workflow artwork were created with the built-in image-generation
tool on 2026-08-28. The user's supplied screenshot was used only as a style
reference; its project name, claims, test count, and deployment badges were not
copied into Secure Share's README.

## Files

- [Banner](secure-share-banner-v2.png): current README hero.
- [How it works](how-it-works.png): upload, grant, download, and revoke workflow.
- [Dashboard](dashboard-ui.png): actual app UI with synthetic local demo data;
  not an AI-generated mockup. No production accounts or files were used.
- [Supplied style reference](readme-style-reference.png): retained as requested;
  it depicts another project, not Secure Share, and is not used as a product screenshot.

Earlier artwork remains available alongside these files. Detailed documentation
has moved to [the technical guide](../technical-guide.md).

## Banner prompt

```text
Use case: ads-marketing.
Create a NEW Secure Share GitHub README banner using Image 1 only as a visual style reference, NOT as content to copy. Match its wide rounded dark panel, fine grid, restrained glow, clean flat typography, left icon tile, spacious text hierarchy and small workflow strip. Approximately 3:1 landscape. Use navy, electric blue, a little mint, white text. This is a flat professional developer-project banner, not a 3D object scene. Replace all OmniFetch branding and media-downloader content.
Exact main title: "Secure Share"
Exact subtitle: "Private file sharing. You control the access."
Exact supporting line: "Upload privately · share with verified users · revoke access"
Small bottom workflow strip, exact labels: "1 UPLOAD" then "2 GRANT" then "3 DOWNLOAD".
Small lower-right outlined badge, exact text: "FLASK REST API" and below it "Python · SQLAlchemy".
Use a simple outlined file-and-shield mark in the left tile. No technology logos, no test counts, no version numbers, no Docker badge, no watermark, no browser frame, no badges or links outside the banner. Do not include the reference's white-page surrounding content. No unsupported security claims. Perfectly readable exact typography, generous margins and no cropped text.
```

## How-it-works prompt

```text
Use case: infographic-diagram.
Asset type: Wide README "How it works" image for Secure Share.
Create a clean flat editorial infographic matching a dark navy developer-project banner: navy #0b1734, blue #3b82f6, mint accents, restrained fine grid, no 3D illustration. Approximately 3:1 landscape, crisp typography at README size.
Exact heading: "How it works"
Four evenly spaced steps across one row, connected left-to-right by simple arrows. Each has a large numbered circle, one simple outline icon, an exact bold title and a short exact caption:
1 title "UPLOAD" caption "Owner stores a private file" icon a file and upload arrow.
2 title "GRANT" caption "Owner approves a verified user" icon person with check.
3 title "DOWNLOAD" caption "Server checks access every time" icon file and down arrow.
4 title "REVOKE" caption "Owner blocks future downloads" icon person with minus.
Small exact footer: "A file ID is not permission."
Clear hierarchy, ample whitespace and high contrast. Illustrate the implemented sequence accurately. No extra claims, no end-to-end encryption label, no API code, no fake UI, no extra text, no watermark. All lettering must be spelled exactly.
```
