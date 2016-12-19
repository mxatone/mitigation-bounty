# Microsoft Mitigation Bounty Bypass proof-of-concepts

This proof-of-concepts show different ways to bypass Windows mitigations in Edge (mainly CFG). A vulnerability is simulated (using a Windbg breakpoint) to gain a read-write anywhere primitive.

To reproduce, launch Edge on one of the html pages (no other instances). Use script\windbg_attach.ps1 to automatically attach Windbg to all Edge instances. Click on the various options and look at the logs or the crash.

More information in these posts:
(Mitigation Bounty — Introduction)[https://medium.com/@mxatone/mitigation-bounty-introduction-e629168faaa3#.i99lopazn]
(Mitigation bounty — From read-write anywhere to controllable calls)[https://medium.com/@mxatone/mitigation-bounty-from-read-write-anywhere-to-controllable-calls-ca1b9c7c0130#.w45wdf9qi]
(Mitigation bounty — 4 techniques to bypass mitigations)[https://medium.com/@mxatone/mitigation-bounty-4-techniques-to-bypass-mitigations-2d0970147f83#.nqp3nj1i0]