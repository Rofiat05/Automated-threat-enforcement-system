from log_reader import read_log_file
from parser import parse_log_line


log_lines = read_log_file("sample_data/auth.log")

for line in log_lines:
    parsed_event = parse_log_line(line)
    print(parsed_event)