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

struct StructStoredDetail {
    rip: u64,
    context: u64,
    index: u32,
    size: u8,
}

impl StructStoredDetail {
    fn new(rip: u64, context: u64, index: u32, size: u8) -> Self {
        StructStoredDetail {
            rip,
            context,
            index,
            size,
        }
    }
}

// Define a global vector to store StructStoredDetail
static mut MY_VECTOR: Vec<StructStoredDetail> = Vec::new();

fn add_to_vector_if_not_exists(rip: u64, context: u64, index: u32, size: u8) -> bool {
    // Safety: Using unsafe to work with the global vector
    unsafe {
        if MY_VECTOR.iter().any(|item| item.rip == rip && item.context == context && item.index == index && item.size == size) {
            // The item is already in the vector, return false
            false
        } else {
            // The item is not in the vector, add it and return true
            MY_VECTOR.push(StructStoredDetail::new(rip, context, index, size));
            true
        }
    }
}

fn print_vector() {
    // Safety: Using unsafe to work with the global vector
    unsafe {
        // Sort the vector by the "index" field
        MY_VECTOR.sort_by(|a, b| a.index.cmp(&b.index));

        for item in &MY_VECTOR {
            println!("rip: {}, context: {}, index: {}, size: {}", item.rip, item.context, item.index, item.size);
        }
    }
}

fn print_structure() {

    let mut current_index = 0;
    let mut first_index = true;
    let mut field_index = 0;

    // Safety: Using unsafe to work with the global vector
    unsafe {
        // Sort the vector by the "index" field
        MY_VECTOR.sort_by(|a, b| a.index.cmp(&b.index));

        println!("typedef struct MY_STRUCT {{");
        for item in &MY_VECTOR {

            if item.index != current_index || first_index == true {

                current_index = item.index;
                first_index = false;

                print!("\t/* 0x{:04x} *\\ ", item.index);

                if item.size == 64 {
                    print!("long long Field{}", field_index);
                } else if item.size == 32 {
                    print!("int Field{}", field_index);
                } else if item.size == 32 {
                    print!("char Field{}", field_index);
                } else {
                    print!("unknown Field{}", field_index);
                }

                field_index = field_index + 1;

                println!(";");
            }



        }
        println!("}}");
    }
}

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

fn zydis_disasm(code: &[u8], rip: u64, single_instruction: bool) -> zydis::Result<()> {

    let fmt = Formatter::intel();
    let dec = Decoder::new64();

    for insn_info in dec.decode_all::<VisibleOperands>(code, rip) {
        let (ip, _raw_bytes, insn) = insn_info?;

        //
        // We use Some(ip) here since we want absolute addressing based on the given
        // instruction pointer. If we wanted relative addressing, we'd use `None` instead
        //
        println!("zydis {:016x} {}", ip, fmt.format(Some(ip), &insn)?);

        if single_instruction { break; }
    }

    Ok(())
}

fn zydis_disasm_interpret(code: &[u8],
                          rip: u64,
                          base: u64,
                          context: u64,
                          single_instruction: bool) -> zydis::Result<()> {

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
        println!("operand_width: {}, length: {}, address_width: {}, opcode: {}, operand_count: {}",
                 insn.operand_width,
                 insn.length,
                 insn.address_width,
                 insn.opcode,
                 insn.operand_count);

        println!("zydis {:016x} {}", ip, fmt.format(Some(ip), &insn)?);

        /* if insn.operand_width != 32 && insn.operand_width != 64 {
            panic!("panic");
        }*/
        add_to_vector_if_not_exists(rip, context, (context - base) as u32, insn.operand_width);

        if single_instruction { break; }
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
    let args: Vec<String> = env::args().collect();

    if args.len() != 3 {
        eprintln!("Usage: {} <hex_address_base> <file_path>", &args[0]);
        std::process::exit(1);
    }

    let hex_address_base = &args[1];
    let file_path = &args[2];

    // let hex_address_base = "ffff870407cc8080";
    // let file_path = "C:\\Users\\sina\\Desktop\\log_open.txt";

    let hex_address_base = hex_address_base.trim();
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
        let mut padding1 = String::new(); // Initialize an empty String
        let mut padding2 = String::new(); // Initialize an empty String

        let diff_len1 = 16 - buffer1.len();
        padding1 = "0".repeat(diff_len1);

        let diff_len2 = 16 - buffer2.len();
        padding2 = "0".repeat(diff_len2);

        let combined_buffer1 = padding1 + buffer1; // Prepend the padding to buffer1
        let combined_buffer2 = padding2 + buffer2; // Prepend the padding to buffer1


        println!("=================================================================");

        println!("json rip: {}", rip);
        println!("json context: {}", context);
        println!("json buffer1: {}", buffer1);
        println!("json buffer2: {}", buffer2);
        println!("json inst_len: {}", inst_len);

        //
        // Reverse the byte order within each pair of characters (buffer1)
        //
        let reversed_hex_string_buffer1: String = combined_buffer1
            .chars()
            .collect::<Vec<_>>()
            .chunks(2)
            .rev()
            .flatten()
            .collect();

        //
        // Add spaces between the reversed pairs (buffer1)
        //
        let formatted_string_buffer1: String = reversed_hex_string_buffer1
            .chars()
            .collect::<Vec<_>>()
            .chunks(2)
            .map(|chunk| chunk.iter().collect::<String>())
            .collect::<Vec<String>>()
            .join(" ");

        //
        // Reverse the byte order within each pair of characters (buffer2)
        //
        let reversed_hex_string_buffer2: String = combined_buffer2
            .chars()
            .collect::<Vec<_>>()
            .chunks(2)
            .rev()
            .flatten()
            .collect();

        //
        // Add spaces between the reversed pairs (buffer2)
        //
        let formatted_string_buffer2: String = reversed_hex_string_buffer2
            .chars()
            .collect::<Vec<_>>()
            .chunks(2)
            .map(|chunk| chunk.iter().collect::<String>())
            .collect::<Vec<String>>()
            .join(" ");


        println!("buffer1: {} combined_buffer1: {}", buffer1, combined_buffer1);
        println!("buffer2: {} combined_buffer2: {}", buffer2, combined_buffer2);
        println!("final buffer: {} {}", formatted_string_buffer1, formatted_string_buffer1);

        let combined_buffer = (formatted_string_buffer1.to_string() + &*formatted_string_buffer2).replace(" ","");

        println!("combined buffer: {}", combined_buffer);

        match hex_string_to_bytes(&*combined_buffer) {
            Ok(bytes) => {

                /*
                //
                // Print the bytes as integers
                //
                for byte in &bytes {
                    println!("0x{:02x}", byte);
                }
                */

                let rip_u64 = parse_hex_to_u64(rip).unwrap();
                let context_u64 = parse_hex_to_u64(context).unwrap();
                let base_u64 = parse_hex_to_u64(hex_address_base).unwrap();

                //
                // Convert the Vec<u8> to a &[u8] slice
                //
                let slice_u8: &[u8] = &bytes;

                match zydis_disasm_interpret(slice_u8, rip_u64, base_u64,context_u64, true) {
                    Ok(result) => {
                        // The disassembly was successful, so you can work with the result
                        // break;
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

    print_vector();
    print_structure();

    Ok(())
}