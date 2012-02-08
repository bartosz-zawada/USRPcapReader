#
# Useless Small Ruby Pcap Reader
#
# Author: BeBour (Bartosz Zawada)
#

# https://github.com/ahobson/ruby-pcap
# http://rubypcap.svn.sourceforge.net/viewvc/rubypcap/doc/index.html

require 'rubygems'
require 'pcap'
require 'optparse'
require 'yaml'
require 'json'
require 'rexml/document'

include Pcap
include REXML

APP_NAME = 'Useless Small Ruby Pcap Reader'
VERSION = 'r17'
REPO = 'https://github.com/BeBouR/USRPcapReader'
AUTHOR = 'BeBouR (Bartosz Zawada)'

# Configuration file
config_file = 'config.yml'
mode = nil

# Method that returns a packet type
def get_packet_type packet
    return :non_ip unless packet.ip?
    return :tcp_ip if packet.tcp?
    return :udp_ip if packet.udp?
    return :other_ip
end

# Parse command line arguments
OptionParser.new do |opts|
    opts.banner = "Usage: #{$0}.rb pcapfile [options]"
    opts.separator " "

    opts.on([:json, :yaml, :xml], "--output FORMAT", "-o", "Select output FORMAT (json, yaml, xml)") do |format|
        # OptionParser accepts j, js, jso without giving the correct option, fixed
        if 'json'.start_with? format
            mode = :json
        elsif 'yaml'.start_with? format
            mode = :yaml
        elsif 'xml'.start_with? format
            mode = :xml
        else
            mode = format
        end
    end

    opts.on("--config FILE", "-c", "Select other configuration file") do |f|
        config_file = f
    end

    opts.separator " "

    opts.on_tail("-h", "--help", "Show this message") do
        puts opts
        exit
    end

    opts.on_tail("-v", "--version", "Prints the version") do
        puts "#{APP_NAME} - #{VERSION}", "Author: #{AUTHOR}", "Project located in #{REPO}"
        exit
    end
end.parse!

# Load configuration file
begin
    config = YAML.load_file config_file
rescue
    $stderr.puts 'Error opening configuration file:' + " '#{config_file}'"
    exit
end

output_mode = mode ? mode : config[:default_output].to_sym
config[:input_file] = ARGV[0]

# Capture
begin
    capture = Capture.open_offline config[:input_file]
rescue
    $stderr.puts 'Error opening file:' + " '#{config[:input_file]}'"
    exit
end

# Extracting packets from capture
a = []
capture.each do |packet|
    # Packet discard
    packet_class = get_packet_type packet
    next if packet_class == :non_ip && config[:discard_non_ip_packets]
    next if packet_class == :tcp_ip && config[:discard_tcp_ip_packets]
    next if packet_class == :udp_ip && config[:discard_udp_ip_packets]
    next if packet_class == :other_ip && config[:discard_other_ip_packets]

    values = {}
    # packet data
    values[config[:data_time]] = packet.time_i if config[:read_time]
    values[config[:data_size]] = packet.size if config[:read_size]
    values[config[:data_caplen]] = packet.caplen if config[:read_caplen]
    values[config[:data_datalink]] = packet.datalink if config[:read_datalink]

    # IP data
    values[config[:data_ip_df]] = packet.ip_df? if config[:read_ip_df]
    values[config[:data_ip_dest]] = packet.ip_dst if config[:read_ip_dest]
    values[config[:data_ip_flags]] = packet.ip_flags if config[:read_ip_flags]
    values[config[:data_ip_hlen]] = packet.ip_hlen if config[:read_ip_hlen]
    values[config[:data_ip_id]] = packet.ip_id if config[:read_ip_id]
    values[config[:data_ip_len]] = packet.ip_len if config[:read_ip_len]
    values[config[:data_ip_mf]] = packet.ip_mf? if config[:read_ip_mf]
    values[config[:data_ip_offset]] = packet.ip_off if config[:read_ip_offset]
    values[config[:data_ip_protocol]] = packet.ip_proto if config[:read_ip_protocol]
    values[config[:data_ip_source]] = packet.ip_src if config[:read_ip_source]
    values[config[:data_ip_sum]] = packet.ip_sum if config[:read_ip_sum]
    values[config[:data_ip_tos]] = packet.ip_tos if config[:read_ip_tos]
    values[config[:data_ip_ttl]] = packet.ip_ttl if config[:read_ip_ttl]
    values[config[:data_ip_version]] = packet.ip_ver if config[:read_ip_version]

    # TCP data

    a << values
end
capture.close

# Packet sort
if config[:sort]
    # Some fucked up formulae to convert strings to symbols and read from config
    if config[:sort_asc]
        a.sort! {|x,y| x[config[config[:sort_by].to_sym]] <=> y[config[config[:sort_by].to_sym]]}
    else
        a.sort! {|x,y| y[config[config[:sort_by].to_sym]] <=> x[config[config[:sort_by].to_sym]]}
    end
end

# Output
if output_mode == :json
    puts JSON.dump({config[:data_main] => a})

elsif output_mode == :yaml
    puts YAML.dump({config[:data_main] => a})

elsif output_mode == :xml
    doc = Document.new
    doc << XMLDecl.new if config[:xml_declaration]
    doc.add_element config[:data_main]
    a.each do |packet|
        p = Element.new config[:data_packet], doc.root
        p.add_attributes packet
    end
    Formatters::Pretty.new(2, true).write(doc, $stdout)
else
    puts "Error: Unknown output format: #{output_mode}"
end
