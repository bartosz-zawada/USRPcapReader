#
# Author: Bartosz Zawada
#

# https://github.com/ahobson/ruby-pcap
# http://rubypcap.svn.sourceforge.net/viewvc/rubypcap/doc/index.html

require 'rubygems'
require 'pcap'
require 'yaml'
require 'json'
require 'rexml/document'

include Pcap
include REXML

def printhelp
    puts "USE: ruby #{$0} [options] PcapFile ", ''
    puts '[options] may be:'
    puts '-j | --json : Output will be in JSON (default)'
    puts '-y | --yaml : Output will be in YAML'
    puts '-x | --xml : Output will be in XML'
    exit
end

return printhelp if ARGV.empty?


file = :NO_FILE

# Load configuration file
config = YAML.load_file 'config.yml'
mode = config[:default_output]

# Parse command line arguments
ARGV.each do |arg|
    if arg[0] == '-'
        mode = 'xml' if arg == '--xml' || arg == '-x'
        mode = 'json' if arg == '--json' || arg == '-j'
        mode = 'yaml' if arg == '--yaml' || arg == '-y'
    else
        # If it's not an option, it ought to be the pcapfile
        if file == :NO_FILE
            file = arg
        else
            return puts 'Only one input file allowed'
        end
    end
end

begin
    capture = Capture.open_offline file
rescue
    puts 'Error opening file:' + " '#{file}'"
    exit
end

a = []
capture.each do |packet|
    values = {}
    values[config[:tag_time]] = packet.time_i if config[:read_time]
    values[config[:tag_size]] = packet.size if config[:read_size]
    a << values
end
capture.close

a.sort! {|x,y| x[config[:sort_by]] <=> y[config[:sort_by]]}
output = {}

if mode == 'json'
    puts JSON.dump({config[:tag_main] => a})

elsif mode == 'yaml'
    puts YAML.dump({config[:tag_main] => a})

elsif mode == 'xml'
    doc = Document.new
    doc.add_element config[:tag_main]
    a.each do |packet|
        p = Element.new config[:tag_packet], doc.root
        packet.each do |key,value|
            e = Element.new key, p
            e.text = value
        end
    end
    puts doc
else
    puts "Error: Unknown output format: #{config[:default_output]}"
end
