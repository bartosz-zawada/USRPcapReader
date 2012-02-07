
#
# Author: Bartosz Zawada
#

# https://github.com/ahobson/ruby-pcap
# http://rubypcap.svn.sourceforge.net/viewvc/rubypcap/doc/index.html

require 'rubygems'
require 'pcap'

include Pcap

puts 'USE:', "ruby #{$0} PcapFile [XML]", '', 'Output format will default to JSON' if ARGV.empty?

a = []

capture = Capture.open_offline ARGV[0]
capture.each { |packet| a << [packet.time_i, packet.size]}
capture.close

a.sort! {|x,y| x[0] <=> y[0]}
a.map! {|packet| "{\"ts\":#{packet[0]},\"sz\":#{packet[1]}}"}
puts '{"Data": [' + a.join(',') + ']}'
