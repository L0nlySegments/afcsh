# AFCSH

A bash-like interface for apple file conduit (AFC).

## Description

This is a bash-like shell to interact with the apple file conduit protocol and manage files on the iPhone. Currently only macOS is supported.


## Installation

You will need to install the Xcode command line tools using this command.

```bash
xcode-select --install
```

After that you can simply clone this repository and run make in the root directory.

```bash
make
```

There should now be an executable under build/afcsh.

## Usage
Simply connect your iPhone to your mac and type:

```bash
./afcsh
```

You will be presented with a bash like shell, with which you can now interact with your iPhones filesystem over AFC.

```bash
iPhone7,2 12.5.5 ~ $
```

The iPhone model and firmware version will be displayed as the prefix as well as the current working directory.

## Features

Upload or download files.  
Create, list and remove files or directories.   
Copy, move or rename files and directories.


## Contributing

Pull requests are welcome. For major changes, please open an issue first
to discuss what you would like to change.