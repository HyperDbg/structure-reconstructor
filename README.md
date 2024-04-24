# Structure Reconstructor

Structure Reconstructor is a Rust project developed to facilitate the reconstruction of data structures from logs gathered by TRM (The Reversing Machine). This tool aims to assist in debugging and reverse engineering by providing a systematic way to recover and understand the memory layout and access patterns captured during runtime.

## Features

- **Automatic Structure Reconstruction**: Automatically generates likely data structure layouts based on log analysis.
- **User-Friendly Output**: Outputs structures in a format that can be easily used or further analyzed.

## Getting Started

These instructions will get you a copy of the project up and running on your local machine for development and testing purposes.

### Prerequisites

Before you begin, ensure you have the latest version of Rust installed on your system. You can install Rust through `rustup`, which can be downloaded and installed from [https://rustup.rs/](https://rustup.rs/).

### Installation

To get a local copy up and running follow these simple steps:

1. **Compile the project:**

   ```bash
   cargo build --release
   ```

2. **Run the tool:**

   ```bash
   cargo run --release -- ffff870407cc8080 .\example\log_generated_from_TRM.txt
   ```
Note: You could gather the same log for your target user-mode and kernel-mode structure using the VMM hypervisor.

## Usage

After running the tool, it will read the input logs from TRM, analyze them, and suggest possible data structure layouts. 
```bash
target\release\reconst.exe <hex_address_base> <file_path>
```

## License

Distributed under the **GPLv3** License. See `LICENSE` for more information.
