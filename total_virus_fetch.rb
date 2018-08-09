require 'virustotal_api'
require 'clipboard'
require 'ipaddress'
require 'json'
require 'open-uri'
require 'resolv'

KEY = 'XXXXXXXXX'
	puts "Will not retain scan results for clean or unrated websites"
begin
	print "Enter URL/IP: "
	url = gets.strip
	copyto = ""
	
	#if input is an IP address, get a resolution and create a url report
	if IPAddress.valid?(url)
	 report = VirustotalAPI::IPReport.find(url, KEY)
	 #get the last ip resolution and create a url report
	 report = VirustotalAPI::URLReport.find(report.report["resolutions"].first["hostname"], KEY)
	else
	 report = VirustotalAPI::URLReport.find(url, KEY)
	 url = Resolv.getaddress(url)
	end
	   geoip = JSON.parse(open('http://ipinfo.io/' + url + '/json').read)
	   # add location info
	   copyto = copyto + "IP: #{geoip["ip"]}\n" + "Country: #{geoip["country"]}\n" + "Region: #{geoip["region"]}\n" + "City: #{geoip["city"]}\n" + "Postal: #{geoip["postal"]}\n"
	   
	if report.exists?
		report.report.delete("scan_id")
		report.report.delete("resource")
		report.report.delete("verbose_msg")
		report.report.delete("filescan_id")
		
		if report.instance_of?(VirustotalAPI::URLReport)
			report.report["scans"].delete_if{ |key,val| val["detected"] == false && (val["result"] == "clean site" || val["result"] == "unrated site") }
		else
			raise "Something went wrong."
		end
		
		report.report.each do |k,v| 
			if v.instance_of?(Hash)
			  copyto = (copyto + "#{k} :\n")
				v.each do |key,value|
					copyto = (copyto + " #{key} : #{value}\n")
					end
			else
				copyto = (copyto + "#{k} : #{v}\n") 
			end
		end
		puts "Results: \n#{copyto}" 
		Clipboard.copy(copyto)
		puts "Complete. Text copied to clipboard. Press Enter to exit"
		gets
		raise Interrupt
	else
		raise "Resource does not exist in the API dataset."
	end
rescue Resolv::ResolvError => e
	puts "#{e.message}" 
	gets
	exit
rescue Interrupt
	exit
rescue Exception => e
	puts e.message
	puts "Try again."
end

	
	
	
