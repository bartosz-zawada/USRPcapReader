#
# Author: Bartosz Zawada
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
VERSION = 'r14'
REPO = 'https://github.com/BeBouR/USRPcapReader'
AUTHOR = 'BeBouR (Bartosz Zawada)'

# Configuration file
config_file = 'config.yml'
mode = nil

# Parse command line arguments
OptionParser.new do |opts|
    opts.banner = "Usage: #{$0}.rb pcapfile [options]"

    opts.separator " "

    opts.on([:json, :yaml, :xml], "--output FORMAT", "-o", "Select output FORMAT (json, yaml, xml)") do |t|
        mode = t
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

output_mode = mode ? mode.to_sym : config[:default_output]
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
    values = {}
    values[config[:tag_time]] = packet.time_i if config[:read_time]
    values[config[:tag_size]] = packet.size if config[:read_size]
    a << values
end
capture.close

# Packet sort
if config[:sort]
    if config[:sort_asc]
        a.sort! {|x,y| x[config[:sort_by]] <=> y[config[:sort_by]]}
    else
        a.sort! {|x,y| y[config[:sort_by]] <=> x[config[:sort_by]]}
    end
end

# Output
if output_mode == :json
    puts JSON.dump({config[:tag_main] => a})

elsif output_mode == :yaml
    puts YAML.dump({config[:tag_main] => a})

elsif output_mode == :xml
    doc = Document.new
    doc << XMLDecl.new if config[:xml_declaration]
    doc.add_element config[:tag_main]
    a.each do |packet|
        p = Element.new config[:tag_packet], doc.root
        p.add_attributes packet
    end
    Formatters::Pretty.new(2, true).write(doc, $stdout)
else
    puts "Error: Unknown output format: #{config[:default_output]}"
end
