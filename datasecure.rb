#!/usr/bin/ruby
# DataSecure v0.1 by Sarvesh Singh. MIT License.
# Runs on the Ruby that ships with every Mac: no installs, no extra packages.
#
#   ruby datasecure.rb              serve the page on http://127.0.0.1:7777
#   ruby datasecure.rb --daily      daily breach check (+ monthly lookup-table refresh)
#   ruby datasecure.rb --lookup IP  which company / country owns an IP
#   ruby datasecure.rb --profile F  write the Private Shield profile to file F

require 'webrick'
require 'json'
require 'net/http'
require 'ipaddr'
require 'securerandom'
require 'socket'
require 'time'

APP   = __dir__
HOME  = ENV['DATASECURE_HOME'] || File.join(Dir.home, '.datasecure')
PORT  = (ENV['DATASECURE_PORT'] || 7777).to_i
ASN_FILE      = File.join(HOME, 'ip2asn-combined.tsv')
ASN_URL       = 'https://iptoasn.com/data/ip2asn-combined.tsv.gz'
SERVICES_FILE = File.join(HOME, 'services.json')
BREACHES_FILE = File.join(HOME, 'breaches.json')
STATE_FILE    = File.join(HOME, 'state.json')
SHIELD_DOH    = 'https://base.dns.mullvad.net/dns-query' # Mullvad "base": ads, trackers, malware, scams
SHIELD_IPS    = ['194.242.2.4', '2a07:e340::4']
UA            = 'DataSecure-v0.1'

def sh(*cmd)
  out = IO.popen(cmd, err: [:child, :out], &:read)
  out.to_s
rescue SystemCallError
  ''
end

def read_json(path, fallback)
  JSON.parse(File.read(path))
rescue StandardError
  fallback
end

def write_json(path, data)
  File.write(path, JSON.generate(data))
end

def https_get(url, headers = {})
  uri = URI(url)
  Net::HTTP.start(uri.host, uri.port, use_ssl: true, open_timeout: 10, read_timeout: 30) do |http|
    req = Net::HTTP::Get.new(uri)
    req['User-Agent'] = UA
    headers.each { |k, v| req[k] = v }
    res = http.request(req)
    raise "#{url} answered #{res.code}" unless res.is_a?(Net::HTTPSuccess)
    res.body
  end
end

# ---------------------------------------------------------------- checkup
# Every check answers ok / bad / unknown. Anything we can't read is unknown, never ok.

SETTINGS = {
  'filevault' => 'x-apple.systempreferences:com.apple.settings.PrivacySecurity.extension?FileVault',
  'firewall'  => 'x-apple.systempreferences:com.apple.Network-Settings.extension?Firewall',
  'updates'   => 'x-apple.systempreferences:com.apple.Software-Update-Settings.extension',
  'lock'      => 'x-apple.systempreferences:com.apple.Lock-Screen-Settings.extension',
  'findmy'    => 'x-apple.systempreferences:com.apple.systempreferences.AppleIDSettings',
  'ads'       => 'x-apple.systempreferences:com.apple.settings.PrivacySecurity.extension?Advertising',
  'profiles'  => 'x-apple.systempreferences:com.apple.Profiles-Settings.extension'
}.freeze

def check_filevault
  out = sh('fdesetup', 'status')
  return ['ok', 'Your disk is encrypted.'] if out.include?('FileVault is On')
  return ['bad', 'Your disk is not encrypted.'] if out.include?('FileVault is Off')
  ['unknown', 'Could not read the FileVault status.']
end

def check_firewall
  out = sh('/usr/libexec/ApplicationFirewall/socketfilterfw', '--getglobalstate')
  return ['ok', 'The firewall is on.'] if out =~ /enabled/i
  return ['bad', 'The firewall is off.'] if out =~ /disabled/i
  ['unknown', 'Could not read the firewall status.']
end

def check_updates
  keys = %w[AutomaticCheckEnabled AutomaticallyInstallMacOSUpdates CriticalUpdateInstall]
  vals = keys.map { |k| sh('defaults', 'read', '/Library/Preferences/com.apple.SoftwareUpdate', k).strip }
  return ['bad', 'Automatic security updates are switched off.'] if vals.include?('0')
  return ['ok', 'Updates install automatically.'] if vals[1] == '1' && vals[2] == '1'
  ['unknown', 'Could not confirm that updates install automatically.']
end

def check_lock
  out = sh('sysadminctl', '-screenLock', 'status')
  return ['ok', 'Your Mac asks for your password right away.'] if out.include?('immediate')
  return ['bad', 'Your Mac does not ask for a password after sleep.'] if out =~ /screenLock is off/i
  if (s = out[/delay is (\d+) seconds/, 1])
    return s.to_i <= 300 ? ['ok', "Password asked after #{s} seconds."] : ['bad', "Password only asked after #{s.to_i / 60} minutes."]
  end
  ['unknown', 'Could not read the screen lock setting.']
end

def check_findmy
  out = sh('plutil', '-convert', 'json', '-o', '-', File.join(Dir.home, 'Library/Preferences/MobileMeAccounts.plist'))
  svc = JSON.parse(out).fetch('Accounts', []).flat_map { |a| a['Services'] || [] }.find { |s| s['Name'] == 'FIND_MY_MAC' }
  return ['unknown', 'Not signed in to iCloud, so Find My could not be checked.'] unless svc
  svc['Enabled'] ? ['ok', 'You can find, lock or wipe this Mac if it is stolen.'] : ['bad', 'Find My Mac is off.']
rescue StandardError
  ['unknown', 'Could not read the Find My setting.']
end

def check_ads
  out = sh('defaults', 'read', 'com.apple.AdLib', 'allowApplePersonalizedAdvertising').strip
  return ['ok', 'Apple does not use your data to pick ads.'] if out == '0'
  return ['bad', 'Apple uses your data to pick ads for you.'] if out == '1'
  ['unknown', 'Could not read the Apple ads setting.']
end

# The shield is on when a known tracker no longer resolves while a normal site still does.
def resolves?(host)
  Addrinfo.getaddrinfo(host, nil).any? { |a| !['0.0.0.0', '::'].include?(a.ip_address) }
rescue SocketError
  false
end

def check_shield
  return ['unknown', 'No internet right now, so the shield could not be tested.'] unless resolves?('example.com')
  return ['bad', 'Trackers are not blocked yet.'] if resolves?('doubleclick.net')
  ['ok', 'Trackers, ads and scam sites are blocked.']
end

CHECKS = {
  'shield'    => ['Private Shield', :check_shield],
  'filevault' => ['Disk encryption (FileVault)', :check_filevault],
  'firewall'  => ['Firewall', :check_firewall],
  'updates'   => ['Automatic updates', :check_updates],
  'lock'      => ['Screen lock', :check_lock],
  'findmy'    => ['Find My Mac', :check_findmy],
  'ads'       => ['Apple personalised ads', :check_ads]
}.freeze

def run_checks
  CHECKS.map do |id, (name, fn)|
    status, detail = send(fn)
    { id: id, name: name, status: status, detail: detail }
  end
end

# ---------------------------------------------------------------- private shield

def shield_profile
  uuid = SecureRandom.uuid.upcase # a fresh id per laptop: this profile is yours alone
  <<~XML
    <?xml version="1.0" encoding="UTF-8"?>
    <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
    <plist version="1.0">
    <dict>
      <key>PayloadContent</key>
      <array>
        <dict>
          <key>DNSSettings</key>
          <dict>
            <key>DNSProtocol</key><string>HTTPS</string>
            <key>ServerURL</key><string>#{SHIELD_DOH}</string>
            <key>ServerAddresses</key>
            <array>#{SHIELD_IPS.map { |ip| "<string>#{ip}</string>" }.join}</array>
          </dict>
          <key>PayloadDisplayName</key><string>DataSecure Private Shield</string>
          <key>PayloadIdentifier</key><string>com.datasecure.shield.dns.#{uuid}</string>
          <key>PayloadType</key><string>com.apple.dnsSettings.managed</string>
          <key>PayloadUUID</key><string>#{SecureRandom.uuid.upcase}</string>
          <key>PayloadVersion</key><integer>1</integer>
        </dict>
      </array>
      <key>PayloadDescription</key><string>Encrypts every website lookup and blocks trackers, ads and scam sites. Made by DataSecure on this Mac.</string>
      <key>PayloadDisplayName</key><string>DataSecure Private Shield</string>
      <key>PayloadIdentifier</key><string>com.datasecure.shield.#{uuid}</string>
      <key>PayloadRemovalDisallowed</key><false/>
      <key>PayloadType</key><string>Configuration</string>
      <key>PayloadUUID</key><string>#{uuid}</string>
      <key>PayloadVersion</key><integer>1</integer>
    </dict>
    </plist>
  XML
end

def install_shield
  path = File.join(HOME, 'DataSecure-Shield.mobileconfig')
  File.write(path, shield_profile)
  system('open', path)
  sleep 1
  system('open', SETTINGS['profiles'])
end

# ---------------------------------------------------------------- leaks

def breaches(max_age = 86_400)
  fresh = File.exist?(BREACHES_FILE) && Time.now - File.mtime(BREACHES_FILE) < max_age
  return read_json(BREACHES_FILE, []) if fresh
  body = https_get('https://haveibeenpwned.com/api/v3/breaches')
  File.write(BREACHES_FILE, body)
  JSON.parse(body)
rescue StandardError
  read_json(BREACHES_FILE, [])
end

def watched
  read_json(SERVICES_FILE, [])
end

def domain_of(text)
  text.to_s.downcase.strip.sub(%r{\Ahttps?://}, '').sub(/\Awww\./, '').split('/').first.to_s
end

def matching_breaches(list, domains)
  list.select { |b| domains.include?(domain_of(b['Domain'])) }
      .map { |b| b.slice('Title', 'Domain', 'BreachDate', 'AddedDate', 'PwnCount', 'DataClasses') }
      .sort_by { |b| b['BreachDate'].to_s }.reverse
end

def notify(title, text)
  esc = ->(s) { s.to_s.gsub(/["\\]/, '') } # outside text (breach titles) can't break out of the AppleScript string
  system('osascript', '-e', %(display notification "#{esc[text]}" with title "#{esc[title]}" sound name "Basso"))
end

def daily(dry_run: false)
  Dir.mkdir(HOME) unless Dir.exist?(HOME)
  state = read_json(STATE_FILE, {})
  since = state['last_breach_check'] || Time.now.utc.iso8601 # first run: start watching from today
  list  = breaches(3600)
  fresh = matching_breaches(list, watched).select { |b| b['AddedDate'].to_s > since }
  fresh.each do |b|
    msg = "#{b['Title']} was hacked. Change that password now, and anywhere you reused it."
    dry_run ? puts("would notify: #{msg}") : notify('DataSecure: data leak', msg)
  end
  puts "checked #{list.size} known breaches, #{fresh.size} new for your services" if dry_run
  write_json(STATE_FILE, state.merge('last_breach_check' => Time.now.utc.iso8601)) unless dry_run || list.empty?
  refresh_asn if !dry_run && (!File.exist?(ASN_FILE) || Time.now - File.mtime(ASN_FILE) > 30 * 86_400)
end

# ---------------------------------------------------------------- where my data goes

def refresh_asn
  tmp = "#{ASN_FILE}.download"
  ok = system('curl', '-fsSL', '-o', "#{tmp}.gz", ASN_URL) && system('gunzip', '-f', "#{tmp}.gz")
  File.rename(tmp, ASN_FILE) if ok && File.size?(tmp)
ensure
  File.delete("#{tmp}.gz") if File.exist?("#{tmp}.gz")
end

def ip_key(text)
  ip = IPAddr.new(text)
  ip.ipv4? ? ip.to_i : (1 << 128) + ip.to_i # IPv4 rows sort before IPv6 rows
end

# Binary search straight on the sorted file (IPv4 rows first, then IPv6), so nothing
# is loaded into memory and no IP ever leaves the laptop.
def lookup(ip)
  return nil unless File.exist?(ASN_FILE)
  key = ip_key(ip)
  File.open(ASN_FILE) do |f|
    # Every line is reachable as "the line after byte mid", and that is monotone in mid.
    lo, hi, best = 0, f.size, nil
    while lo < hi
      mid = (lo + hi) / 2
      f.seek(mid)
      f.gets if mid > 0
      line = f.gets
      if line && ip_key(line.split("\t", 2)[0]) <= key
        best = line
        lo = mid + 1
      else
        hi = mid
      end
    end
    return nil unless best
    first, last, asn, country, org = best.chomp.split("\t")
    return nil if asn == '0' || ip_key(last) < key
    { asn: asn.to_i, country: country, org: org }
  end
rescue IPAddr::InvalidAddressError
  nil
end

KNOWN = %w[APPLE GOOGLE MICROSOFT AMAZON AKAMAI CLOUDFLARE FASTLY FACEBOOK META
           ZOOM SPOTIFY NETFLIX DROPBOX ADOBE WHATSAPP TWITTER LINKEDIN GITHUB EDGECAST
           LEVEL3 KPN ZIGGO TMOBILE VODAFONE ODIDO INCAPSULA OVH HETZNER DIGITALOCEAN].freeze

def private_ip?(ip)
  a = IPAddr.new(ip)
  a.private? || a.loopback? || a.link_local?
rescue IPAddr::InvalidAddressError
  true
end

def connections
  out = sh('lsof', '+c', '0', '-nP', '-i', '-Fcn')
  app = nil
  rows = Hash.new(0)
  out.each_line do |line|
    case line[0]
    when 'c' then app = line[1..-1].strip
    when 'n'
      remote = line[1..-1].strip.split('->')[1] or next
      ip = remote.sub(/:\d+\z/, '').delete('[]')
      next if private_ip?(ip)
      info = lookup(ip) || {}
      rows[[app, info[:org] || 'Unknown', info[:country] || '']] += 1
    end
  end
  rows.map do |(name, org, country), n|
    known = KNOWN.any? { |k| org.upcase.delete('-').include?(k) }
    { app: name, company: org, country: country, connections: n, known: known }
  end.sort_by { |r| [r[:known] ? 1 : 0, r[:app].downcase] }
end

# ---------------------------------------------------------------- web server

ALLOWED_HOSTS = ["127.0.0.1:#{PORT}", "localhost:#{PORT}"].freeze

def guard(req)
  # Blocks DNS-rebinding (wrong Host) and other websites pressing our buttons (wrong Origin).
  return false unless ALLOWED_HOSTS.include?(req['Host'])
  return true if req.request_method == 'GET'
  origin = req['Origin'].to_s.sub(%r{\Ahttp://}, '')
  ALLOWED_HOSTS.include?(origin) && req.content_type.to_s.start_with?('application/json')
end

def json(res, data, code = 200)
  res.status = code
  res['Content-Type'] = 'application/json'
  res.body = JSON.generate(data)
end

def body(req)
  JSON.parse(req.body.to_s)
rescue JSON::ParserError
  {}
end

def serve
  Dir.mkdir(HOME) unless Dir.exist?(HOME)
  server = WEBrick::HTTPServer.new(BindAddress: '127.0.0.1', Port: PORT,
                                   Logger: WEBrick::Log.new(File::NULL), AccessLog: [])
  route = lambda do |path, &blk|
    server.mount_proc(path) do |req, res|
      next json(res, { error: 'blocked' }, 403) unless guard(req)
      res['Cache-Control'] = 'no-store'
      res['X-Frame-Options'] = 'DENY'
      blk.call(req, res)
    end
  end

  route.call('/') do |req, res|
    next json(res, { error: 'not found' }, 404) unless req.path == '/'
    res['Content-Type'] = 'text/html; charset=utf-8'
    res['Content-Security-Policy'] = "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; frame-ancestors 'none'"
    res.body = File.read(File.join(APP, 'index.html'))
  end

  route.call('/api/checks') { |_, res| json(res, run_checks) }

  route.call('/api/open') do |req, res|
    url = SETTINGS[body(req)['id']]
    next json(res, { error: 'unknown setting' }, 400) unless url
    system('open', url)
    json(res, ok: true)
  end

  route.call('/api/shield/install') do |_, res|
    install_shield
    json(res, ok: true)
  end

  # Only the first 5 characters of the password's SHA-1 fingerprint ever arrive here.
  route.call('/api/password-range') do |req, res|
    prefix = body(req)['prefix'].to_s.upcase
    next json(res, { error: 'bad prefix' }, 400) unless prefix.match?(/\A[0-9A-F]{5}\z/)
    begin
      json(res, range: https_get("https://api.pwnedpasswords.com/range/#{prefix}", 'Add-Padding' => 'true'))
    rescue StandardError
      json(res, { error: 'Could not reach the leak database. Check your internet.' }, 502)
    end
  end

  route.call('/api/services') do |req, res|
    if req.request_method == 'POST'
      domains = Array(body(req)['domains']).map { |d| domain_of(d) }.reject(&:empty?).uniq.first(200)
      write_json(SERVICES_FILE, domains)
    end
    list = breaches
    json(res, domains: watched, breaches: matching_breaches(list, watched), known: list.size)
  end

  route.call('/api/test-notification') do |_, res|
    notify('DataSecure', 'Alerts work. You will see leaks here.')
    json(res, ok: true)
  end

  route.call('/api/connections') do |_, res|
    json(res, table: File.exist?(ASN_FILE), rows: connections)
  end

  route.call('/api/open-app') do |req, res|
    app = { 'safari' => 'Safari', 'chrome' => 'Google Chrome', 'firefox' => 'Firefox', 'passwords' => 'Passwords' }[body(req)['id']]
    next json(res, { error: 'unknown app' }, 400) unless app
    json(res, ok: system('open', '-a', app))
  end

  trap('TERM') { server.shutdown }
  trap('INT') { server.shutdown }
  server.start
end

case ARGV[0]
when '--daily'   then daily(dry_run: ARGV.include?('--dry-run'))
when '--lookup'  then puts JSON.generate(lookup(ARGV[1]))
when '--profile' then File.write(ARGV[1], shield_profile)
when '--checks'  then puts JSON.pretty_generate(run_checks)
else serve
end
