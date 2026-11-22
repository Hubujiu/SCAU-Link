# Third party notices

The native authentication core uses the Ruijie hash implementation from
MiniEAP, https://github.com/updateing/minieap, commit
983fd4a5851d4a344fab92666c5cdb83f26b2294. The copied files and upstream license
are in third_party/minieap_hashes. Original copyright and license notices
remain in those files. The project is distributed under GPL-3.0.

Local modifications: computePwd's temporary buffer was increased from 40 to
1024 bytes, with input lengths bounded by the C++ caller; standard MD5 is
provided by Windows CNG. The upstream hash algorithm and its reference data
are otherwise unchanged. The integer-type compatibility header was updated
to use stdint.h on modern MSVC without Unix-only includes.

WinPcap/Npcap are runtime dependencies, loaded from their installed system
locations. Their drivers and binaries are not redistributed by this project.

The native UI includes vector paths from Lucide 0.468.0, matching the HTML
design assets. Lucide is distributed under the ISC license. Its copyright
and license notice are in third_party/lucide/LICENSE.

The application mark in assets/app-icon.svg is original project artwork,
distributed under the project GPL-3.0 license; it is separate from Lucide.

The school self-service HTTPS module statically links OpenSSL 3.5.9,
https://www.openssl.org/, licensed under Apache License 2.0. The unmodified
corresponding upstream source archive, license and pinned source checksum
are included in third_party/openssl (under source/ in binary distributions).
Local build configuration is in scripts/build_openssl.py. No OpenSSL DLLs,
provider modules or executables from other installed applications are used.

The build bootstrap downloads a checksum-pinned portable Strawberry Perl
5.42.3.1 solely as a build tool. It is not part of the distributed application
or installed system-wide; its upstream licenses remain in the downloaded
build/deps archive. The runtime application does not use Perl.

The optional native installer is built with unmodified Inno Setup 7.1.1 by
Jordan Russell and Martijn Laan, https://jrsoftware.org/. Its license and
compiler provenance are in third_party/inno-setup. The compiler is downloaded
with a pinned checksum and used in portable mode under build/deps; the compiler
IDE and its file associations are not installed system-wide.

The installation edition includes the x64 Microsoft Visual C++ 2022 CRT
redistributable files msvcp140.dll, msvcp140_atomic_wait.dll, vcruntime140.dll
and vcruntime140_1.dll from the Visual Studio Build Tools VC/Redist directory.
These unmodified Microsoft redistributables are installed beside the app,
never in the Windows directory. They are subject to Microsoft's Visual Studio
license and distributable-code terms, not the project's GPL. The build verifies
their Microsoft signatures and records hashes in docs/runtime-manifest.json.
See https://learn.microsoft.com/cpp/windows/redistributing-visual-cpp-files
and https://learn.microsoft.com/visualstudio/releases/2022/redistribution.
