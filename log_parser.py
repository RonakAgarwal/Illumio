import sys
from collections import defaultdict
from typing import Dict, List, Tuple

class FlowLogParser:
    def __init__(self, lookup_file: str):
        self.lookup_table: Dict[Tuple[int, str], str] = self.load_lookup_table(lookup_file)
        self.tag_counts: Dict[str, int] = defaultdict(int)
        self.port_protocol_counts: Dict[Tuple[int, str], int] = defaultdict(int)

    def load_lookup_table(self, filename: str) -> Dict[Tuple[int, str], str]:
        lookup_table = {}
        try:
            with open(filename, 'r') as file:
                next(file)  # Skip header
                for line in file:
                    port, protocol, tag = line.strip().split(',')
                    lookup_table[(int(port), protocol.lower())] = tag
        except FileNotFoundError:
            print(f"Error: Lookup table file '{filename}' not found.")
            sys.exit(1)
        except Exception as e:
            print(f"Error reading lookup table: {e}")
            sys.exit(1)
        return lookup_table

    def parse_flow_log(self, log_file: str):
        try:
            with open(log_file, 'r') as file:
                for line in file:
                    self.process_log_entry(line.strip())
        except FileNotFoundError:
            print(f"Error: Flow log file '{log_file}' not found.")
            sys.exit(1)
        except Exception as e:
            print(f"Error reading flow log: {e}")
            sys.exit(1)

    def process_log_entry(self, log_entry: str):
        fields = log_entry.split()
        dst_port = int(fields[6])
        protocol = self.get_protocol(int(fields[7]))
        
        tag = self.lookup_table.get((dst_port, protocol), "untagged")
        self.tag_counts[tag] += 1
        self.port_protocol_counts[(dst_port, protocol)] += 1

    @staticmethod
    def get_protocol(protocol_number: int) -> str:
        protocols = {6: 'tcp', 17: 'udp', 1: 'icmp'}
        return protocols.get(protocol_number, str(protocol_number))

    def generate_output(self, output_file: str):
        try:
            with open(output_file, 'w') as file:
                file.write("Tag Counts:\nTag,Count\n")
                for tag, count in self.tag_counts.items():
                    file.write(f"{tag},{count}\n")
                
                file.write("\nPort/Protocol Combination Counts:\nPort,Protocol,Count\n")
                for (port, protocol), count in self.port_protocol_counts.items():
                    file.write(f"{port},{protocol},{count}\n")
            print(f"Output written to {output_file}")
        except Exception as e:
            print(f"Error writing output: {e}")
            sys.exit(1)

def main():
    lookup_file = input("Enter the path to the lookup table file: ").strip()
    log_file = input("Enter the path to the flow log file: ").strip()
    output_file = input("Enter the path for the output file: ").strip()

    parser = FlowLogParser(lookup_file)
    parser.parse_flow_log(log_file)
    parser.generate_output(output_file)

if __name__ == "__main__":
    main()