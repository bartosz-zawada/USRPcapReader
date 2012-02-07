#
# Pcap Reader
#
# Lee ficheros .pcap que se le pasan como argumento por línea
# de comandos
#
# Autor: Bartosz Zawada
#
# https://github.com/ahobson/ruby-pcap
# http://rubypcap.svn.sourceforge.net/viewvc/rubypcap/doc/index.html
#

require 'rubygems'
require 'pcap'

include Pcap

puts 'USE:', "ruby #{$0} file1 [file2...]" if ARGV.empty?

ARGV.each do |file|
    a = []

    capture = Capture.open_offline file
    capture.each { |packet| a << '{"ts":' + packet.time_i.to_s + ', "sz":' + packet.size.to_s + '}' }
    capture.close

    out = File.open (file + '.data'), 'w'
    out.puts '{"Data": [' + a.join(',') + ']}'
    out.close
end