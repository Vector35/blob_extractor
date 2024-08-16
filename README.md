# Blob Extractor
Author: **Vector 35 Inc.**

_Binary Ninja plugin for extracting files from container formats_

## Description

Blob Extractor is a Binary Ninja plugin that leverages the [Unblob API](https://github.com/onekey-sec/unblob) to
identify and extract compressed archives, file-systems, and other blobs embedded in container binaries such as flash
dumps or firmware images.

## Installation Instructions

The following dependencies are required by this plugin:

* [unblob](https://github.com/onekey-sec/unblob) - Python package for extracting files from container formats
* libmagic - Native libmagic file type identification library
* [python-magic](https://github.com/ahupp/python-magic) - Python bindings for libmagic

### Darwin

1. Install the `libmagic` native library

```
brew install libmagic
```

2. Install the dependency Python packages for the Python version in use by Binary Ninja. If you are using your system's
Python interpeter, these packages can be installed using PIP.

```
pip3 install unblob python-magic
```

3. Clone the repository into the Binary Ninja `plugins` directory

```
git clone git@github.com:Vector35/blob-extractor.git "/Users/$USER/Library/Application Support/Binary Ninja/plugins/blob-extractor"
```

### Linux

1. Install the `libmagic` native library

```
sudo apt-get install libmagic1
```

2. Install the dependency Python packages for the Python version in use by Binary Ninja.

```
pip3 install unblob python-magic
```

3. Clone the repository into the Binary Ninja `plugins` directory

```
git clone git@github.com:Vector35/blob-extractor.git "~/.binaryninja/plugins/blob-extractor"
```

### Windows

Windows is not supported by this plugin. Blob Extractor depends on `libmagic`, Unblob, and Unblob's extractor utilities.
These dependencies do not run on Windows.

## Extractor Utilities

Unblob uses external utilities for file extraction. After installing Unblob (via the installation instructions above)
run the following command to identify missing external extractor utilties:

```
> unblob --show-external-dependencies
The following executables found installed, which are needed by unblob:
    7z                          ✓
    debugfs                     ✗
    jefferson                   ✓
    lz4                         ✓
    lziprecover                 ✓
    lzop                        ✓
    sasquatch                   ✗
    sasquatch-v4be              ✗
    simg2img                    ✓
    ubireader_extract_files     ✓
```

Missing extractor utilities must be installed manually. Blob Extractor will still run without external extractor
utilities. However, it will be unable to extract certain blob formats.

## License

This plugin is released under an [MIT license](./LICENSE).
