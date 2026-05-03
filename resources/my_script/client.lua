-- Example client-side script
-- This file will be obfuscated by tools/crx.py before deployment

local playerName = GetPlayerName(PlayerId())

-- Show a welcome notification
AddEventHandler('onClientResourceStart', function(resourceName)
    if GetCurrentResourceName() ~= resourceName then return end

    local msg = string.format("Welcome, %s!", playerName)
    SetNotificationTextEntry("STRING")
    AddTextComponentString(msg)
    DrawNotification(false, true)

    print("[my_script] client loaded for " .. playerName)
end)

-- Example: listen for a server event
RegisterNetEvent('my_script:notify')
AddEventHandler('my_script:notify', function(text)
    SetNotificationTextEntry("STRING")
    AddTextComponentString(text)
    DrawNotification(false, true)
end)
