<div align="center">
  <img src="https://github.com/user-attachments/assets/33926387-ea26-42e6-93d1-e14fa5f5fd99"/>
</div>
<br/>

[![](https://github.com/qtc-de/rpv-ghidra/actions/workflows/build.yml/badge.svg?branch=main)](https://github.com/qtc-de/rpv-ghidra/actions/workflows/build.yml)
[![](https://img.shields.io/badge/version-1.0.0-blue)](https://github.com/qtc-de/rpv-ghidra/releases)
[![](https://img.shields.io/badge/language-v%20%26%20vue-blue)](https://vlang.io/)
[![](https://img.shields.io/badge/license-GPL%20v3.0-blue)](https://github.com/qtc-de/rpv-ghidra/blob/master/LICENSE)

*rpv-ghidra* is a [Ghidra](https://github.com/NationalSecurityAgency/ghidra) extension for analyzing
Windows RPC interfaces. After importing an [rpv-snapshot](https://github.com/qtc-de/rpv-web/wiki/Snapshots)
the extension visualizes the available RPC interfaces, security callbacks and allows easy navigation
between them. In theory, the extension also applies function signatures and adds all data types contained
within the decompiled IDL data from the snapshot. However, this feature is currently buggy and I have no
idea why it does not work. Pull requests are welcome :)

![rpv-ghidra](https://github.com/user-attachments/assets/e2dd9be3-3f8e-4d7c-9b9a-3cb490d63b60)


### Installation

----

The recommended way of installing *rpv-ghidra* is downloading the pre-build version from the
[release](https://github.com/qtc-de/rpv-ghidra/releases/latest) section of this project. After
download, you can install the extension in Ghidra by using `File -> Install Extensions`. For
more information, read the [official documentation](https://ghidra-sre.org/InstallationGuide.html#GhidraExtensionNotes)

If you want to build from source, you can use the [docker-compose.yml](docker-compose.yml) file
from this repository. It expects the extension source to be present in the current working directory
within a folder named `rpv-ghidra`. A Ghidra installation is also required and by default expected
in the current working directory under a folder named `ghidra`.


### Resources

----

Icons used within the extension were kindly provided by <a target="_blank" href="https://icons8.com">Icons8</a>.
