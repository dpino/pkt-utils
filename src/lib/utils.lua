module(...,package.seeall)

function format (text, env)
   for kword in text:gmatch("{([a-zA-Z0-9_]+)}") do
      text = text:gsub("{"..kword.."}", env[kword])
   end
   return text
end
