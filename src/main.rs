use std::{env, io};
use std::env::var;
use std::num::ParseIntError;
use std::fs::File;
use std::io::{BufRead, BufReader};
use zydis::*;


#[rustfmt::skip]
static CODE: &'static [u8] = &[
    0x51, 0x8D, 0x45, 0xFF, 0x50, 0xFF, 0x75, 0x0C, 0xFF, 0x75, 0x08,
    0xFF, 0x15, 0xA0, 0xA5, 0x48, 0x76, 0x85, 0xC0, 0x0F, 0x88, 0xFC,
    0xDA, 0x02, 0x00,
];

fn zydis_len_disasm(code: &[u8]) -> zydis::Result<u8> {
    let fmt = Formatter::intel();
    let dec = Decoder::new64();

    // 0 is the address for our code.
    for insn_info in dec.decode_all::<VisibleOperands>(code, 0) {
        let (ip, _raw_bytes, insn) = insn_info?;
        let len = insn.length;
        return Ok(len);
    }
    Ok(0)
}

fn zydis_disasm(code: &[u8], rip: u64) -> zydis::Result<()> {

    let fmt = Formatter::intel();
    let dec = Decoder::new64();

    for insn_info in dec.decode_all::<VisibleOperands>(code, rip) {
        let (ip, _raw_bytes, insn) = insn_info?;

        println!(
            "zydis len: {}",
            zydis_len_disasm(_raw_bytes).expect("err, unable to decode the buffer")
        );

        //
        // We use Some(ip) here since we want absolute addressing based on the given
        // instruction pointer. If we wanted relative addressing, we'd use `None` instead
        //
        println!("zydis 0x{:016X} {}", ip, fmt.format(Some(ip), &insn)?);
    }

    Ok(())
}

fn hex_string_to_bytes(hex_string: &str) -> std::result::Result<Vec<u8>, String> {
    // Ensure that the input string has an even number of characters
    if hex_string.len() % 2 != 0 {
        return Err("Hex string length must be even".to_string());
    }

    //
    // Create a vector to hold the bytes
    //
    let mut bytes = Vec::new();

    //
    // Iterate over the hex characters by 2 (1 byte) and convert to u8
    //
    for i in (0..hex_string.len()).step_by(2) {
        let hex_pair = &hex_string[i..i + 2];
        if let Ok(byte) = u8::from_str_radix(hex_pair, 16) {
            bytes.push(byte);
        } else {
            return Err(format!("Invalid hex pair: {}", hex_pair));
        }
    }

    Ok(bytes)
}

fn parse_hex_to_u32(hex_str: &str) -> std::result::Result<u32, ParseIntError> {
    u32::from_str_radix(hex_str.trim_start_matches("0x"), 16)
}

fn parse_hex_to_u64(hex_str: &str) -> std::result::Result<u64, ParseIntError> {
    u64::from_str_radix(hex_str.trim_start_matches("0x"), 16)
}

fn main() -> io::Result<()>  {

    //
    // Get the command-line arguments
    //

    /*
    let args: Vec<String> = env::args().collect();

    if args.len() != 3 {
        eprintln!("Usage: {} <hex_address> <file_path>", &args[0]);
        std::process::exit(1);
    }

    let hex_address = &args[1];
    let file_path = &args[2];
     */

    let hex_address = "ffff870407cc8080";
    let file_path = "C:\\Users\\sina\\Desktop\\log_open.txt";

    let hex_address = hex_address.trim();
    let file_address = file_path.trim();

    let file = File::open(file_address)?;
    let reader = BufReader::new(file);

    for line_result in reader.lines() {

        let line = line_result?;
        let json_str: &str = line.as_str(); // Convert String to &str

        // println!("{}", line);
        let json: serde_json::Value = serde_json::from_str(json_str).expect("JSON was not well-formatted");

        //
        // Access individual fields
        //
        let rip = json["rip"].as_str().unwrap();
        let context = json["context"].as_str().unwrap();
        let buffer1 = json["buffer1"].as_str().unwrap();
        let buffer2 = json["buffer2"].as_str().unwrap();
        let inst_len = json["inst_len"].as_str().unwrap();

        println!("=================================================================");
        println!("rip: {}", rip);
        println!("context: {}", context);
        println!("buffer1: {}", buffer1);
        println!("buffer2: {}", buffer2);
        println!("inst_len: {}", inst_len);

        let combined_buffer = buffer1.to_string() + buffer2;


        match hex_string_to_bytes(&*combined_buffer) {
            Ok(bytes) => {
                // Print the bytes as integers

                /*
                 byte in &bytes {
                    println!("0x{:02x}", byte);
                }
                */

                let rip_u64 = parse_hex_to_u64(rip).unwrap();

                //
                // Convert the Vec<u8> to a &[u8] slice
                //

                //
                // Convert the Vec<u8> to a &[u8] slice
                //
                let slice_u8: &[u8] = &bytes;

                match zydis_disasm(slice_u8, rip_u64) {
                    Ok(result) => {
                        // The disassembly was successful, so you can work with the result
                    },
                    Err(err) => {
                        // The disassembly encountered an error. You can handle it gracefully here.
                        // For example, print an error message or log the error.
                        println!("Disassembly error: {}", err);
                    }
                }

            },
            Err(err) => {
                println!("Error: {}", err);
            }
        }
    }
    Ok(())
}