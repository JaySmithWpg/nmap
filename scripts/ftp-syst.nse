local ftp = require "ftp"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"

description = [[
Executes a SYST command against the target FTP server.
]]

author = "Jay Smith"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe"}

portrule = shortport.port_or_service(21, "ftp")

local USER_NAME = "anonymous"
local PASSWORD = "IEUser@"

message_ftp = function(socket, buffer, message)
  local status, error_message = socket:send(message .. "\r\n")
  if not status then
    stdnse.debug1("Error sending %s: %s", message, error_message)
    return
  end

  local code, response = ftp.read_reply(buffer)
  if not code then
    stdnse.debug1("Error receiving %s: %s", message, response)
    return
  end
  return code, response
end


action = function(host, port)
  local socket, response = ftp.connect(host, port)
  local buffer = stdnse.make_buffer(socket, "\r?\n")

  if not socket then
    stdnse.debug1("Failed to connect to service: %s", response)
    return
  end

  -- Read banner
  local code, response = ftp.read_reply(buffer)

  if code and (code == 220 or code == 530) then
    code, response = message_ftp(socket, buffer, "USER " .. USER_NAME)
  end

  -- code 332 (need account for login) is rarely used, but when it is used,
  -- it can either come as a response to the USER or PASS command.
  -- Sometimes the password needs to be re-sent. We handle this by looping
  -- the following block twice.
  for i=1,2 do
    if code and code == 332 then
      --need account for login. Send a blank one for anonymous.
      code, response = message_ftp(socket, buffer, "ACCT")
    end
    if code and code == 331 then
      code, response = message_ftp(socket, buffer, "PASS " .. PASSWORD)
    end
  end
  
  if not code then
    return
  end

  if code == 530 then
    return "User " .. USER_NAME .. " login failed."
  end

  if code ~= 230 then
    stdnse.debug1("Unexpected response: %d %q", code, response)
    return
  end

  -- We should now be connected as the specified user. Send the SYST.
  code, response = message_ftp(socket, buffer, "SYST")
  if not code then
    return
  end
  return string.format("%d: %s", code, response)
end
