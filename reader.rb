
#
# Author: Bartosz Zawada
#

# https://github.com/ahobson/ruby-pcap
# http://rubypcap.svn.sourceforge.net/viewvc/rubypcap/doc/index.html

require 'rubygems'
require 'pcap'

include Pcap

def printhelp
puts "USE: ruby #{$0} [options] PcapFile ", ''
puts '[options] may be:'
puts '-x | --xml : Output will be in XML instead of JSON'
puts '-h | --help : prints this'
exit
end

return printhelp if ARGV.empty?

mode = :JSON
file = :NO_FILE

ARGV.each do |arg|
    if arg[0] == '-'
        mode = :XML if arg == '--xml' || arg == '-x'
        printhelp if arg == '--help' ||  arg =='-h'
    else
        #If it's not an option, it ought to be the pcapfile
        if file == :NO_FILE
            file = arg
        else
            return puts 'Only one input file allowed'
        end
    end
end

a = []

begin
    capture = Capture.open_offline file
rescue
    puts 'Error opening file:' + " '#{file}'"
    exit
end

capture.each { |packet| a << [packet.time_i, packet.size]}
capture.close

a.sort! {|x,y| x[0] <=> y[0]}

if mode == :JSON
    a.map! {|packet| "{\"ts\":#{packet[0]},\"sz\":#{packet[1]}}"}
    puts '{"Data": [' + a.join(',') + ']}'
else
    a.map! {|packet| "  <packet>\n    <ts>#{packet[0]}</ts>\n    <sz>#{packet[1]}</sz>\n  </packet>\n" }
    puts "<data>\n" + a.join("\n") + '</data>'
end
