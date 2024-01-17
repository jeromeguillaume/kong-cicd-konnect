    return function()
      kong.log.notice("custom *** BEGIN ***")

      local auhtN_Header = kong.request.get_header("Authorization")
      if (not auhtN_Header) then
          kong.log.debug("Unable to get 'Authorization' header")
          return
      end

      local utils = require "kong.tools.utils"
      local entries = utils.split(auhtN_Header, " ")
      if #entries ~= 2 then
          kong.log.debug("Unable to get a consistent 'Authorization' header")
          return
      end

      local xDynamicHeader = "x-jwt-authorization-type"
      if entries[1] ~= 'Bearer' then
          kong.log.debug("Unable to get a 'Bearer'")
      end
      local x_jwt = entries[2]
      kong.service.request.set_header(xDynamicHeader, "Bearer")
      
      kong.log.notice("x_jwt: " .. x_jwt)
      local jwt_payload = ""
      -- Get 1st . (dot)
      local b4, e4 = string.find(x_jwt, "%.")
      local b5, e5
      -- Get 2nd . (dot)
      if e4 ~= nil then
        b5, e5 = string.find(x_jwt, "%.", e4 + 1)
      end
      -- If we failed to find JWT payload
      if e4 == nil or e5 == nil then
        kong.log.err ( "Failure to extract payload from 'X-JWT-Assertion'")
        return ""
      end
      
      jwt_payload = string.sub(x_jwt, e4 + 1, e5 - 1)
      
      -- bas64 decoding of JWT payload
      local decode_base64 = ngx.decode_base64
      local decoded = decode_base64(jwt_payload)
      local cjson = require("cjson.safe").new()
      local x_jwt_json, err = cjson.decode(decoded)
      -- If we failed to base64 decode
      if err then
        kong.log.err ( "Failure to decode base64 payload 'X-JWT-Assertion'")
        return ""
      end

      kong.service.request.add_header ("x-jwt-iss", x_jwt_json.iss)
      kong.service.request.add_header ("x-jwt-sub", x_jwt_json.sub)
      kong.log.notice("custom *** END ***")
    end