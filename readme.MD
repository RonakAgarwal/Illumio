# Flow Log Parser

## Assumptions and Limitations

1. **Log Format**: Only supports the default AWS VPC Flow Logs format. Custom log formats are not supported.
2. **Log Version**: Only version 2 of VPC Flow Logs is supported. Entries from other versions will be skipped with a warning.
3. **Lookup Table Format**: Must be in CSV format with exactly three columns: dstport, protocol, and tag. The first line is assumed to be a header and is skipped.
4. **Protocol Handling**: Protocol numbers 6, 17, and 1 are mapped to TCP, UDP, and ICMP respectively. Other protocol numbers are treated as strings.
5. **Port Numbers**: All port numbers are assumed to be valid integers.
6. **File Sizes**: Can handle flow log files up to 10 MB. Lookup table can have up to 10000 mappings.
7. **Character Encoding**: All input files are assumed to be in UTF-8 encoding.
8. **Error Handling**: Exits on critical errors (e.g., file not found). Malformed lines in the flow log are skipped without notification.
9. **Case Sensitivity**: Protocol matching in the lookup table is case-insensitive. Tag names preserve their case as specified in the lookup table.
10. **Output Format**: Generates a CSV file with two sections: tag counts and port/protocol combination counts.
11. **Environment**: System is running a recent version of Python with access to standard libraries.


## Installation

1. Clone repository:
   ```
   git clone https://github.com/RonakAgarwal/Illumio.git
   ```
2. Navigate to the project directory:
   ```
   cd illumio
   ```

## Usage

Run the program using Python:

```
python log_parser.py
```

When prompted, enter the paths for:
- Lookup table file
- Flow log file
- Output file

Example:
```
Enter the path to the lookup table file: lookup_table.txt
Enter the path to the flow log file: flow_log.txt
Enter the path for the output file: output.txt
```

The program will process the input and generate the output file.

## Tests done

Ran sample flow logs and mappings sourced from the Amazon VPC sample documentation of flow logs and checked if the output files were accurate.

## Analysis

For particularly large datasets, parallel processing may be neceesary to increase efficiency. Since the instructions said to avoid
any form of non-default libraries, I did not attempt to include that in the implementation. 

